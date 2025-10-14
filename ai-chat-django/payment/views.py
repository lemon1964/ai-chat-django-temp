# payment/views.py
import json
import uuid
from decimal import Decimal, ROUND_HALF_UP
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from yookassa import Payment, Refund
from .models import KassaPayment, PaymentEventLog, Subscription
from .hooks import webhook_waiting_for_capture, webhook_succeeded, webhook_canceled, webhook_refund
from .utils import (
    create_receipt,
    create_payment_data,
    apply_coupon,
    update_payment_status,
    confirm_payment_in_kassa,
    is_valid_webhook_signature,
    get_base_amount,
    recent_inflight_payment_exists,
    has_active_forever_purchase,
    compute_final_amount,
)
from django.core.management import call_command
import logging
logger = logging.getLogger('payment')

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def process_kassa(request):
    """
    Создание первичного платежа в YooKassa.
    Защиты:
      - дубль подписки: блокируем повтор для активной monthly/yearly;
      - дубль forever: блокируем повторную бессрочную покупку, если прошлый платёж успешен и не возвращён;
      - анти-даблклик: недавний незавершённый запуск того же типа.
    """
    subscription_type = (request.data.get('subscription_type') or '').lower()
    coupon_code = (request.data.get('coupon_code') or '').strip()

    # 0) Базовая цена
    try:
        base_amount = get_base_amount(subscription_type)  # Decimal
    except Exception:
        return Response({"error": "Неизвестный тип подписки"}, status=400)

    # 1) Блок «повторной покупки»
    if subscription_type in ('monthly', 'yearly'):
        # вернём ещё и дату следующего списания для UX
        existing = Subscription.objects.filter(
            user=request.user,
            plan=subscription_type,
            status='active',
            next_charge_at__gt=timezone.now(),
        ).first()
        if existing:
            return Response({
                "error": "У вас уже есть активная подписка этого типа.",
                "plan": existing.plan,
                "next_charge_at": existing.next_charge_at.isoformat(),
            }, status=status.HTTP_409_CONFLICT)

    if subscription_type == 'forever':
        if has_active_forever_purchase(request.user):
            return Response({
                "error": "Бессрочная покупка уже оформлена. Повторная оплата не требуется."
            }, status=status.HTTP_409_CONFLICT)

    # 2) Анти-даблклик (недавний запуск того же типа)
    if recent_inflight_payment_exists(request.user, subscription_type, window_seconds=90):
        return Response(
            {"error": "Платёж уже создаётся, подождите пару секунд и проверьте ссылку на оплату."},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    # 3) Скидка (одинаковая логика с validate_coupon)
    discount_percentage = 0
    if coupon_code:
        try:
            discount_percentage = apply_coupon(coupon_code, subscription_type)
        except ValueError as e:
            return Response({"error": str(e)}, status=400)

    amount, discount_amount = compute_final_amount(base_amount, discount_percentage)

    # 4) Чек и описание
    description = (
        "Ежемесячная подписка" if subscription_type == "monthly" else
        "Годовая подписка" if subscription_type == "yearly" else
        "Оплата за покупку навсегда"
    )
    receipt = create_receipt(request.user, description, amount)

    # 5) Локальная запись
    payment = KassaPayment.objects.create(
        user=request.user,
        amount=amount,
        subscription_type=subscription_type,
        coupon_code=coupon_code or '',
        discount=int(discount_amount),  # для отображения в админке
        status='pending',
    )

    # 6) YooKassa: создаём платёж
    payment_data = create_payment_data(
        amount=amount,
        description=description,
        local_payment_id=payment.id,
        subscription_type=subscription_type,
        receipt=receipt
    )
    idem = str(uuid.uuid4())

    try:
        kassa_payment = Payment.create(payment_data, idem)
        payment.kassa_payment_id = kassa_payment.id
        payment.save(update_fields=['kassa_payment_id', 'updated_at'])

        return Response(
            {'session_url': kassa_payment.confirmation.confirmation_url},
            status=200
        )
    except Exception:
        payment.delete()
        return Response({'error': 'Ошибка при создании платежа'}, status=500)   


@api_view(['POST'])
@permission_classes([IsAdminUser])
def confirm_payment(request):
    """
    Аварийное подтверждение:
    1) читаем удалённый статус в ЮKassa;
    2) если waiting_for_capture — делаем capture (идемпотентно);
    3) если уже succeeded — просто синхронизируем локальный статус;
    4) иначе — сообщаем фактический удалённый статус (ничего не ломаем).
    """
    payment_id = request.data.get('payment_id')
    if not payment_id:
        return Response({"error": "payment_id required"}, status=400)

    kp = KassaPayment.objects.filter(kassa_payment_id=payment_id).first()
    if not kp:
        return Response({"error": "Payment not found in DB"}, status=404)

    # 1) фактическое состояние в ЮKassa
    try:
        remote = Payment.find_one(payment_id)
    except Exception as e:
        return Response({"error": "Kassa lookup error", "detail": str(e)}, status=502)

    remote_status = getattr(remote, "status", None)

    # 2) если ждёт capture — подтверждаем на сумму из БД
    if remote_status == "waiting_for_capture":
        capture_resp = confirm_payment_in_kassa(payment_id, kp.amount)
        if not capture_resp:
            return Response({"error": "Kassa capture error"}, status=502)

        if update_payment_status(payment_id, capture_resp):
            return Response({"status": "captured_and_synced"}, status=200)
        return Response({"error": "Local update failed after capture"}, status=409)

    # 3) уже succeeded — просто синхронизируем локально
    if remote_status == "succeeded":
        if update_payment_status(payment_id, remote):
            return Response({"status": "already_captured_synced"}, status=200)
        return Response({"error": "Local update failed (succeeded)"}, status=409)

    # 4) прочие состояния — информируем, ничего не ломаем
    return Response({"status": "not_capturable", "remote_status": remote_status}, status=409)


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def kassa_webhook(request):
    """
    Базовый каркас вебхука:
    - пропускаем запрос в local, в проде фильтруем IP (utils.is_valid_webhook_signature);
    - читаем JSON, аккуратно извлекаем event и object.id;
    - пишем PaymentEventLog (applied=False, note='unknown_event');
    - возвращаем 200 OK, чтобы YooKassa не ретраила.
    """
    # 0) IP-проверка (в local пропускается)
    if not is_valid_webhook_signature(request):
        return Response(status=403)

    # 1) JSON
    try:
        data = json.loads(request.body.decode('utf-8'))
    except Exception:
        return Response(status=400)

    event = (data.get('event') or '').strip()
    obj = data.get('object', {}) or {}
    obj_id = obj.get('id') or ''

    # 2) журнальная запись (пока без бизнес-логики)
    PaymentEventLog.objects.create(
        event_id=obj_id,
        event_type=event,
        payload=data,
        applied=False,
        note='unknown_event',
    )

    try:
        logger.info(json.dumps(
            {'kind': 'webhook_income', 'event': event, 'id': obj_id},
            ensure_ascii=False
        ))
    except Exception:
        pass

    # 3) всегда 200 — подтверждаем приём уведомления
    return Response(status=200)


# Основной обработчик webhook
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def kassa_webhook(request):
    # 0) IP-проверка
    if not is_valid_webhook_signature(request):
        return Response(status=403)

    # 1) читаем JSON
    try:
        data = json.loads(request.body.decode('utf-8'))
    except Exception:
        return Response(status=400)

    event = (data.get('event') or '').strip()
    obj = data.get('object', {}) or {}
    obj_id = obj.get('id') or ''  # для payment.* — это id платежа; для refund.* — id возврата

    # 2) пишем лог (pre-apply)
    log = PaymentEventLog.objects.create(
        event_id=obj_id,
        event_type=event,
        payload=data,
        applied=False,
        note=None,
    )
    try:
        logger.info(json.dumps(
            {'kind': 'webhook_income', 'event': event, 'id': obj_id},
            ensure_ascii=False
        ))
    except Exception:
        pass

    # 3) маршрутизация
    if event == 'payment.waiting_for_capture':
        resp = webhook_waiting_for_capture(data)
    elif event == 'payment.succeeded':
        resp = webhook_succeeded(data)
    elif event == 'payment.canceled':
        resp = webhook_canceled(data)
    elif event == 'refund.succeeded':
        resp = webhook_refund(data)
    else:
        # неизвестные события подтверждаем 200, чтобы YooKassa не ретраила (и фиксируем заметку)
        PaymentEventLog.objects.filter(pk=log.pk).update(note='unknown_event')
        return Response(status=200)

    # 4) пост-фикс: помечаем applied в зависимости от результата
    status_code = getattr(resp, 'status_code', 200)
    if status_code == 200:
        PaymentEventLog.objects.filter(pk=log.pk).update(applied=True)
    else:
        PaymentEventLog.objects.filter(pk=log.pk).update(note=f'handler_status={status_code}')

    return resp


@api_view(['POST'])
@permission_classes([IsAdminUser])
# @permission_classes([AllowAny])
def process_refund(request):
    # Получаем необходимые данные из запроса
    payment_id = request.data.get('payment_id')
    amount = request.data.get('amount')
    description = request.data.get('description', '')  # Комментарий к возврату
    receipt = request.data.get('receipt')  # Данные для чека (необязательные)

    if not payment_id or not amount:
        return Response({'error': 'payment_id and amount are required'}, status=400)
    
    # Достаем пользователя, связанного с этим платежом
    try:
        payment = KassaPayment.objects.get(kassa_payment_id=payment_id)
    except KassaPayment.DoesNotExist:
        return Response({'error': 'Payment not found'}, status=404)

    # Достаем данные для чека, если не переданы
    if not receipt:
        receipt = create_receipt(payment.user, payment.subscription_type, amount)

    # Параметры для возврата
    refund_data = {
        "amount": {
            "value": str(amount),  # Сумма возврата
            "currency": "RUB"
        },
        "payment_id": payment_id,
        "description": description,
        "receipt": receipt
    }

    try:
        # Создаем возврат
        refund = Refund.create(refund_data)
        
        # Отладка: смотрим структуру объекта refund
        # print("Refund object:", refund)

        # Преобразуем объект в словарь
        if hasattr(refund, '__dict__'):
            refund_data = vars(refund)
        else:
            refund_data = refund  # если это уже словарь, работаем с ним напрямую
        
        # Печатаем все поля объекта, чтобы увидеть его структуру
        # print("Refund data dictionary:", refund_data)
        
        # Извлекаем информацию о возврате (authorization details)
        refund_authorization_details = refund_data.get('refund_authorization_details', None)
        
        # Записываем авторизационные детали, если они существуют
        if refund_authorization_details:
            payment.authorization_details = refund_authorization_details
            print("Updated payment.authorization_details:", payment.authorization_details)
        else:
            print("No refund authorization details found.")
        
        # Сохраняем изменения в базе данных
        payment.save()

        # Возвращаем успешный ответ с id возврата
        return Response({
            'refund_id': refund.id,
            'status': refund.status,
            'amount': refund.amount,
        }, status=200)
    
    except Exception as e:
        print(f"Error processing refund: {e}")
        return Response({'error': 'Error processing refund'}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def validate_coupon(request):
    """
    Быстрая валидация купона:
    вход: { subscription_type, coupon_code }
    выход: { valid, base_amount, final_amount, discount_percentage } или { valid:false, error, base_amount }
    Цены и проценты считаются ровно как в process_kassa (чтобы «до/после» совпадало с итоговым чеком).
    """
    subscription_type = request.data.get('subscription_type')
    coupon_code = (request.data.get('coupon_code') or "").strip()

    try:
        base_amount = get_base_amount(subscription_type)  # Decimal
    except Exception:
        return Response({"error": "Unknown subscription_type"}, status=400)

    if not coupon_code:
        # Без купона — просто вернуть базовую цену
        return Response({
            "valid": True,
            "base_amount": str(base_amount),
            "final_amount": str(base_amount),
            "discount_percentage": "0",
        })

    # Проверка купона теми же правилами, что и при оплате
    try:
        discount_percentage = apply_coupon(coupon_code, subscription_type)  # Decimal или int
    except ValueError as e:
        return Response({
            "valid": False,
            "error": str(e),
            "base_amount": str(base_amount),
        }, status=200)

    # Ровно как в process_kassa: итоговую сумму «рублём вниз» (int)
    discount_amount = (base_amount * Decimal(discount_percentage) / Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    final_amount = (base_amount - discount_amount).quantize(Decimal("1"), rounding=ROUND_HALF_UP)  # целые рубли

    return Response({
        "valid": True,
        "base_amount": str(base_amount),
        "final_amount": str(final_amount),
        "discount_percentage": str(discount_percentage),
    }, status=200)




@api_view(['POST'])
@permission_classes([AllowAny])
def process_recurring_payment(request):
    # Получаем payment_method_id из запроса
    payment_method_id = request.data.get('payment_method_id')
    
    if not payment_method_id:
        return Response({'error': 'payment_method_id is required'}, status=400)
    
    # Ищем исходный платеж в базе данных по kassa_payment_id (payment_method_id)
    try:
        original_payment = KassaPayment.objects.get(kassa_payment_id=payment_method_id)
    except KassaPayment.DoesNotExist:
        return Response({'error': 'Original payment not found'}, status=404)
    
    # Достаем данные для чека из оригинального платежа
    receipt = create_receipt(original_payment.user, original_payment.subscription_type, original_payment.amount)
    
    # Создаем новый платеж, копируя только нужные поля (исключаем поле 'id')
    payment_data = {
        'amount': original_payment.amount,
        'subscription_type': original_payment.subscription_type,
        'coupon_code': original_payment.coupon_code,
        'discount': original_payment.discount,
        'status': 'pending',  # Статус платежа пока "pending"
        'created_at': timezone.now(),  # Устанавливаем новую дату
        'updated_at': timezone.now(),
        'user': original_payment.user,
        'information_payment': "Повторный",  # Уникальный идентификатор для повторного платежа
        'kassa_payment_status': "waiting_for_capture",  # Статус платежа в Кассе
        'income_amount': original_payment.income_amount,  # Сумма после комиссии
    }

    # Создаем новый экземпляр платежа на основе данных старого
    payment = KassaPayment.objects.create(**payment_data)
    
    # Параметры для нового платежа
    payment_data = create_payment_data(payment.amount, payment.subscription_type, payment.id, payment.subscription_type, receipt, payment_method_id)

    # Генерируем уникальный idempotence_key
    idempotence_key = str(uuid.uuid4())

    try:
        # Создаем новый платеж, используя сохраненный метод оплаты
        new_payment = Payment.create(payment_data, idempotence_key)
        
        # Обновляем созданный платеж в базе
        payment.kassa_payment_id = new_payment.id  # Обновляем kassa_payment_id на новый ID

        # Сохраняем все обновления в базе
        payment.save()
        # Платеж обновится в базе и в Кассе по хуку payment.succeeded
        # Без хука его можно обновить вручную через POST запрос на /api/payment/confirm-payment/
        
        return Response({
            'payment_id': new_payment.id
        }, status=200)
    except Exception as e:
        # Удаляем созданный платеж из базы, если произошла ошибка при запросе в Кассу
        payment.delete()  # Удаляем платеж из базы
        return Response({'error': f'Error creating recurring payment: {str(e)}'}, status=500)


@api_view(['POST'])
@permission_classes([AllowAny])
def charge_subscriptions_http(request):
    expected = getattr(settings, 'CRON_SECRET', None)
    token = request.headers.get('X-CRON-SECRET')
    if (not expected) or (token != expected):
        return Response({'detail': 'Not found'}, status=404)

    call_command('charge_subscriptions', limit=100)
    return Response({'status': 'ok'})


# Отписка, в текущей реализации немедленно лишит юзера премиума.
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def unsubscribe(request):
    plan = (request.data.get('plan') or '').lower()
    if plan not in ('monthly','yearly'):
        return Response({'error': 'invalid plan'}, status=400)

    sub = Subscription.objects.filter(user=request.user, plan=plan, status='active').first()
    if not sub:
        return Response({'error': 'no active subscription'}, status=404)

    sub.status = 'canceled'
    sub.save(update_fields=['status','updated_at'])
    return Response({'status': 'canceled'})