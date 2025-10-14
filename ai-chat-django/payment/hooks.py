# ai-chat-django/payment/hooks.py
from datetime import datetime
from django.utils.timezone import make_aware
from rest_framework.response import Response
from .models import KassaPayment, Subscription
from .utils import confirm_payment_in_kassa, update_payment_status
from decimal import Decimal, InvalidOperation
from yookassa import Payment as KPayment


def webhook_waiting_for_capture(data):
    obj = data.get('object', {}) or {}
    payment_id = obj.get('id')
    # amount можно не использовать, но пусть будет fallback для confirm_payment_in_kassa
    amount_value = (obj.get('amount', {}) or {}).get('value')

    if not payment_id:
        return Response(status=200)

    kp = KassaPayment.objects.filter(kassa_payment_id=payment_id).first()
    if not kp:
        return Response(status=200)  # не наш платёж — ACK

    # Идемпотентность: подтверждаем только из "waiting_for_capture"
    if kp.kassa_payment_status != 'waiting_for_capture':
        return Response(status=200)  # повтор/запаздалый хук

    # Подтверждаем с устойчивым idempotence_key
    if confirm_payment_in_kassa(payment_id, amount_value):
        return Response(status=200)

    return Response({"error": "Error confirming payment"}, status=500)


def webhook_succeeded(data):
    obj = data.get('object', {}) or {}
    payment_id = obj.get('id')
    amount_obj = obj.get('amount', {}) or {}
    amount_value = amount_obj.get('value')
    currency = amount_obj.get('currency')
    meta = obj.get('metadata', {}) or {}

    kp = KassaPayment.objects.filter(kassa_payment_id=payment_id).first()
    if not kp:
        return Response(status=200)

    if kp.kassa_payment_status in ('succeeded', 'canceled', 'refund_succeeded'):
        return Response(status=200)

    try:
        amt = Decimal(str(amount_value))
    except (InvalidOperation, TypeError):
        return Response(status=200)

    if amt != kp.amount:
        return Response(status=200)
    if currency != 'RUB':
        return Response(status=200)
    if str(meta.get('payment_id')) != str(kp.id):
        return Response(status=200)

    # тянем детальный платёж
    kassa_resp = KPayment.find_one(payment_id)

    # 1) синхронизируем платёж локально
    updated = update_payment_status(payment_id, kassa_resp)

    # 2) если это monthly/yearly — создаём/обновляем подписку
    # (важно: этот блок ДОЛЖЕН выполняться до return)
    sub_type = (meta.get('subscription_type') or '').lower()
    if updated and sub_type in ('monthly','yearly'):
        pm = getattr(kassa_resp, 'payment_method', None)
        pm_id = getattr(pm, 'id', None)
        pm_saved = getattr(pm, 'saved', False)

        if pm_id and pm_saved:
            sub, _ = Subscription.objects.get_or_create(
                user=kp.user,
                plan=sub_type,
                defaults={
                    'status': 'active',
                    'amount': kp.amount,
                    'currency': 'RUB',
                    'payment_method_id': pm_id,
                    'fails_count': 0,
                    'last_payment_id': kp.kassa_payment_id,
                }
            )
            sub.payment_method_id = pm_id
            sub.amount = kp.amount
            sub.currency = 'RUB'
            sub.status = 'active'
            sub.fails_count = 0
            sub.last_payment_id = kp.kassa_payment_id
            sub.schedule_next()
            sub.save()
        else:
            # способ оплаты не сохранён — автосписаний не будет
            kp.information_payment = (kp.information_payment or '') + " [autopay=off]"
            kp.save(update_fields=['information_payment'])

    # 3) отвечаем ОК (важно вернуть 200, чтобы Касса не ретраила)
    return Response(status=200)


def webhook_canceled(data):
    payment_id = data.get('object', {}).get('id')

    if payment_id:
        try:
            # Ищем платеж в базе данных по kassa_payment_id
            kassa_payment = KassaPayment.objects.get(kassa_payment_id=payment_id)

            # Обновляем статус платежа на "Canceled"
            kassa_payment.kassa_payment_status = 'canceled'
            kassa_payment.status = 'failed'  # Платеж не завершился, поэтому статус "failed"
            
            # Записываем причину отмены в information_payment
            cancellation_reason = data.get('object', {}).get('cancellation_details', {}).get('reason', 'Unknown')
            kassa_payment.information_payment = cancellation_reason  # Причина отмены

            # Заполняем поле expires_at, если оно присутствует в данных
            card_info = data.get('object', {}).get('payment_method', {}).get('card', {})
            if card_info:
                expiry_year = card_info.get('expiry_year')
                expiry_month = card_info.get('expiry_month')
                if expiry_year and expiry_month:
                    try:
                        # Формируем строку вида "YYYY-MM-01" и преобразуем в datetime
                        expires_str = f"{expiry_year}-{expiry_month}-01"  # Устанавливаем 1-е число месяца
                        expires_naive = datetime.fromisoformat(expires_str)
                        
                        # Преобразуем наивную дату в aware (с учетом часового пояса)
                        kassa_payment.expires_at = make_aware(expires_naive)
                    except ValueError:
                        print(f"Ошибка преобразования даты: {expires_str}")

            # Заполняем поле payment_method
            payment_method = data.get('object', {}).get('payment_method', {})
            if payment_method:
                kassa_payment.payment_method = payment_method  # Сохраняем метод оплаты

            # Заполняем поле authorization_details
            authorization_details = data.get('object', {}).get('authorization_details', {})
            if authorization_details:
                kassa_payment.authorization_details = authorization_details  # Сохраняем детали авторизации

            # Сохраняем все изменения в базе
            kassa_payment.save()

            # Логируем успешное обновление
            print(f"Платеж {kassa_payment.id} отменен. Статус обновлен на 'canceled'. Причина отмены: {cancellation_reason}")
            return Response(status=200)

        except KassaPayment.DoesNotExist:
            print(f"Платеж с ID {payment_id} не найден.")
            return Response({'error': 'Платеж не найден'}, status=404)
        except Exception as e:
            print(f"Ошибка при обработке отмены: {e}")
            return Response({'error': 'Ошибка при обработке отмены'}, status=500)

    return Response({'error': 'payment_id is missing'}, status=400)


# Обработка события refund.succeeded (заглушка)
def webhook_refund(data):
    # print(f"Получен webhook с событием refund.succeeded: {json.dumps(data, indent=4)}")

    payment_id = data.get('object', {}).get('payment_id')
    refund_status = data.get('object', {}).get('status')
    cancellation_details = data.get('cancellation_details', {})
    description = data.get('object', {}).get('description', '')
    
    if payment_id:
        try:
            kassa_payment = KassaPayment.objects.get(kassa_payment_id=payment_id)
            
            # Записываем информацию о возврате
            if refund_status == 'succeeded':    # Успешний возврат
                kassa_payment.kassa_payment_status = 'refund_succeeded'
                kassa_payment.status = 'refund'
                kassa_payment.information_payment = description  # Описание возврата
            else:   # Не успешный возврат
                # kassa_payment.kassa_payment_status = 'succeeded'  // Оставляем прежний статус и вообще убираем строку
                kassa_payment.status = 'refund_failed'  # Для неудачного возврата статус 'failed'
                kassa_payment.information_payment = cancellation_details.get('reason', 'Unknown reason')  # Причина неуспешного возврата
            
            # Сохраняем данные возврата в базу
            kassa_payment.save()
            
            return Response(status=200)
        except KassaPayment.DoesNotExist:
            print(f"Платеж с ID {payment_id} не найден.")
            return Response({'error': 'Payment not found'}, status=404)
    return Response(status=200)
