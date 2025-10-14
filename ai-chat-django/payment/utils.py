# payment/utils.py
from decimal import Decimal, ROUND_HALF_UP
from django.utils import timezone
from django.conf import settings
from datetime import datetime, timedelta
import ipaddress
from django.utils.timezone import make_aware
from yookassa import Payment
from .models import KassaPayment, Subscription, Coupon

import logging
logger = logging.getLogger(__name__)

# Базовые цены (руб.) — используем Decimal для корректной арифметики с деньгами.
BASE_PRICES = {
    "monthly": Decimal("300"),
    "yearly": Decimal("2500"),
    "forever": Decimal("5000"),
}

def get_base_amount(subscription_type: str) -> Decimal:
    """
    Возвращает базовую цену по типу подписки.
    Если тип неизвестен — бросает ValueError, чтобы вьюха отдала понятную 400.
    """
    if subscription_type not in BASE_PRICES:
        raise ValueError("Unknown subscription_type")
    return BASE_PRICES[subscription_type]

def create_receipt(user, description, amount):
    """
    Функция для создания данных чека для Кассы.
    """
    return {
        "customer": {
            "full_name": user.name,
            "email": user.email,
        },
        "items": [
            {
                "description": description,
                "quantity": "1.00",
                "amount": {
                    "value": str(amount),
                    "currency": "RUB"
                },
                "vat_code": "2",  # Пример кода НДС
                "payment_mode": "full_payment",
                "payment_subject": "commodity",
                "country_of_origin_code": "RU",
                "product_code": "Бизнес проект LLM",
                "excise": "0.00",  # Пример акциза
                "supplier": {
                    "name": "LLM",
                    "phone": "123456789",
                    "inn": "123106123985"
                }
            },
        ]
    }

def create_payment_data(amount, description, local_payment_id, subscription_type, receipt, payment_method_id=None):
    """
    Единая сборка тела платежа:
    - первый платёж (без payment_method_id): redirect + save_payment_method для monthly/yearly
    - повторный (с payment_method_id): БЕЗ confirmation, capture=true
    """
    save_pm = (subscription_type in ('monthly', 'yearly'))

    data = {
        "amount": {"value": str(amount), "currency": "RUB"},
        "capture": False,  # первый платёж проводим с отложенным capture (наш привычный поток)
        "confirmation": {"type": "redirect", "return_url": f"{settings.FRONT_URL}/payment/success"},
        "description": description,
        "receipt": receipt,
        "metadata": {"payment_id": local_payment_id, "subscription_type": subscription_type},
    }
    if save_pm:
        data["save_payment_method"] = True

    # Рекуррент: saved card → без confirmation, capture=true
    if payment_method_id:
        data["payment_method_id"] = payment_method_id
        data.pop("confirmation", None)
        data["capture"] = True              # пусть ЮKassa капчурит сама (вебхук сразу succeeded)

    return data


def update_payment_status(payment_id, kassa_response):
    """
    Обновляем платёж по ответу Кассы (после capture/succeeded).
    Берём income_amount из ответа провайдера, а не считаем сами.
    """
    try:
        # kassa_response может быть объектом SDK или словарём
        if hasattr(kassa_response, '__dict__'):
            kassa_data = vars(kassa_response)
        else:
            kassa_data = kassa_response  # уже словарь

        kp = KassaPayment.objects.get(kassa_payment_id=payment_id)

        # Статус успеха
        kp.kassa_payment_status = 'succeeded'
        kp.status = 'completed'

        # ---- income_amount из ответа ----
        income_raw = None

        # 1) объект SDK: kassa_response.income_amount?.value
        if hasattr(kassa_response, 'income_amount') and getattr(kassa_response, 'income_amount'):
            income_obj = getattr(kassa_response, 'income_amount')
            # у SDK-объекта поле value — строка типа "4825.00"
            value_str = getattr(income_obj, 'value', None)
            if value_str:
                income_raw = value_str

        # 2) приватные поля объекта SDK (через vars) или чистый dict (из вебхука)
        if not income_raw:
            maybe_income = (
                kassa_data.get('_PaymentResponse__income_amount')
                or kassa_data.get('income_amount')
            )
            if maybe_income:
                if isinstance(maybe_income, dict):
                    income_raw = maybe_income.get('value')
                else:
                    # на всякий случай, если это объект с атрибутом value
                    income_raw = getattr(maybe_income, 'value', None)

        # Записываем, если нашли
        if income_raw:
            try:
                kp.income_amount = Decimal(str(income_raw))
            except Exception:
                # если по какой-то причине сконвертить не удалось — оставим как было
                pass

        # ---- способ оплаты (как было) ----
        payment_method = kassa_data.get('_PaymentResponse__payment_method', None)
        if payment_method:
            kp.payment_method = {
                "type": payment_method.type,
                "id": payment_method.id,
                "status": payment_method.status,
                "title": payment_method.title,
                "card": {
                    "first6": payment_method.card.first6,
                    "last4": payment_method.card.last4,
                    "expiry_year": payment_method.card.expiry_year,
                    "expiry_month": payment_method.card.expiry_month,
                    "card_type": payment_method.card.card_type,
                    "issuer_country": payment_method.card.issuer_country
                }
            }

        # срок действия карты (как было)
        card_info = kp.payment_method.get('card', {}) if kp.payment_method else {}
        if card_info:
            expiry_year = card_info.get('expiry_year')
            expiry_month = card_info.get('expiry_month')
            if expiry_year and expiry_month:
                try:
                    expires_str = f"{expiry_year}-{expiry_month}-01"
                    kp.expires_at = make_aware(datetime.fromisoformat(expires_str))
                except ValueError:
                    pass

        # authorization_details (как было)
        auth_det = kassa_data.get('_PaymentResponse__authorization_details')
        if auth_det:
            kp.authorization_details = {
                "rrn": auth_det.rrn,
                "auth_code": auth_det.auth_code,
                "three_d_secure": {
                    "applied": getattr(auth_det.three_d_secure, 'applied', False),
                    "method_completed": getattr(auth_det.three_d_secure, 'method_completed', False),
                    "challenge_completed": getattr(auth_det.three_d_secure, 'challenge_completed', False),
                }
            }

        kp.save()
        # print(f"Платеж {kp.id} подтвержден и статус обновлен на 'succeeded'. income_amount={kp.income_amount}")
        return True

    except KassaPayment.DoesNotExist:
        print(f"Платеж с ID {payment_id} не найден.")
        return False


def confirm_payment_in_kassa(payment_id, amount=None):
    """
    Подтверждение платежа в ЮKassa с устойчивым idempotence_key.
    - Если платёж есть в БД — берём сумму из БД и стабильный ключ из модели.
    - Если нет (fallback) — используем переданный amount и разовый ключ.
    """
    try:
        kp = KassaPayment.objects.filter(kassa_payment_id=payment_id).first()

        if kp:
            # стабильный ключ на основе ID платежа
            if not kp.capture_idem_key:
                kp.capture_idem_key = f"capture:{payment_id}"
                kp.save(update_fields=["capture_idem_key"])
            value = str(kp.amount)
            idem_key = kp.capture_idem_key
        else:
            if amount is None:
                return None
            value = str(amount)
            idem_key = f"capture:{payment_id}"

        resp = Payment.capture(
            payment_id,
            {"amount": {"value": value, "currency": "RUB"}},
            idem_key,
        )
        return resp
    except Exception as e:
        print(f"Error confirming payment in Kassa: {e}")
        return None


def is_valid_webhook_signature(request):
    """
    ЮKassa webhook IP-check (минималистично):
    - DJANGO_ENV=local → пропускаем (для туннелей);
    - берём IP из X-Forwarded-For[0] → X-Real-IP → REMOTE_ADDR;
    - поддержка ::ffff:IPv4 и IPv6 CIDR; без шумных принтов.
    """
    ALLOWED_IP_RANGES = [
        '185.71.76.0/27',
        '185.71.77.0/27',
        '77.75.153.0/25',
        '77.75.156.11',
        '77.75.156.35',
        '77.75.154.128/25',
        '2a02:5180::/32',
    ]

    # дев-режим — не блокируем туннели
    if getattr(settings, 'DJANGO_ENV', 'local') == 'local':
        return True

    raw_xff = (request.META.get('HTTP_X_FORWARDED_FOR') or '').strip()
    x_real  = (request.META.get('HTTP_X_REAL_IP') or '').strip()
    remote  = (request.META.get('REMOTE_ADDR') or '').strip()

    ip = ''
    if raw_xff:
        ip = raw_xff.split(',')[0].strip()
    if not ip:
        ip = x_real or remote

    if ip.startswith('::ffff:'):
        ip = ip[7:]

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        if settings.DEBUG:
            logger.debug('KASSA webhook invalid IP format: %r', ip)
        return False

    for rng in ALLOWED_IP_RANGES:
        try:
            if '/' in rng:
                if ip_obj in ipaddress.ip_network(rng, strict=False):
                    return True
            else:
                if ip == rng:
                    return True
        except ValueError:
            continue

    if settings.DEBUG:
        logger.debug('KASSA webhook IP not allowed: %s', ip)
    return False


def recent_inflight_payment_exists(user, subscription_type: str, window_seconds: int = 90) -> bool:
    """
    Был ли у пользователя запуск такого же платежа в последние N секунд:
    - локальная запись создана, но платёж ещё не финализирован.
    """
    window_start = timezone.now() - timedelta(seconds=window_seconds)
    return (
        KassaPayment.objects.filter(
            user=user,
            subscription_type=subscription_type,
            created_at__gte=window_start,
            status='pending',
        ).exists()
        or
        KassaPayment.objects.filter(
            user=user,
            subscription_type=subscription_type,
            created_at__gte=window_start,
            kassa_payment_status='waiting_for_capture',
        ).exists()
    )

def has_active_subscription(user, plan: str) -> bool:
    """
    Есть ли активная подписка (monthly/yearly) с будущим next_charge_at.
    """
    if plan not in ('monthly', 'yearly'):
        return False
    return Subscription.objects.filter(
        user=user,
        plan=plan,
        status='active',
        next_charge_at__gt=timezone.now(),
    ).exists()


def has_active_forever_purchase(user) -> bool:
    """
    Покупал ли пользователь бессрочно (успешный платёж без возврата).
    Разрешаем повторную покупку только если прошлый forever был полностью возвращён.
    """
    return KassaPayment.objects.filter(
        user=user,
        subscription_type='forever',
        kassa_payment_status='succeeded',
    ).exclude(status='refund').exists()

# Расчёт итоговой цены и скидки
def compute_final_amount(base_amount, discount_percentage):
    """
    Ровно тот же расчёт, что и во вьюхах:
    - скидку считаем с копейками
    - итог — целые рубли (bankers/half-up → int)
    Возвращаем (final_int, discount_decimal).
    """
    base = Decimal(str(base_amount))
    pct = Decimal(str(discount_percentage or 0))
    discount_amount = (base * pct / Decimal('100')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    final_amount = (base - discount_amount).quantize(Decimal('1'), rounding=ROUND_HALF_UP)
    return int(final_amount), discount_amount


def apply_coupon(coupon_code, subscription_type):
    try:
        coupon = Coupon.objects.get(code=coupon_code, active=True)

        # Проверяем, что купон подходит для выбранного типа подписки
        if not coupon.apply_to_subscription(subscription_type):
            raise ValueError("Этот купон не подходит для выбранной подписки.")

        # Проверяем, действует ли купон в текущем сезоне
        current_date = timezone.now().date()
        if not coupon.is_valid():
            raise ValueError("Купон просрочен.")

        # Возвращаем скидку
        return coupon.discount
    except Coupon.DoesNotExist:
        raise ValueError("Неверный или неактивный купон.")
