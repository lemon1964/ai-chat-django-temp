# ai-chat-django/payment/tests.py
import json
import pytest
import uuid
from types import SimpleNamespace
from decimal import Decimal
from django.utils import timezone
from rest_framework import status
from django.contrib.auth import get_user_model
from django.test import override_settings
from payment.models import KassaPayment, Subscription, PaymentEventLog

User = get_user_model()

WEBHOOK_URL = "/api/payment/webhook-kassa/"

def make_kp(user, kassa_id="pmt-123", amount=Decimal("300.00"), sub_type="monthly"):
    """Фабрика локальной записи платежа под входящий вебхук."""
    return KassaPayment.objects.create(
        user=user,
        amount=amount,
        subscription_type=sub_type,
        coupon_code="",
        discount=0,
        status="pending",
        kassa_payment_status="waiting_for_capture",
        kassa_payment_id=kassa_id,
    )

def webhook_payload(kassa_id, kp_id, sub_type, amount="300.00", event="payment.succeeded"):
    """Ровно та структура, которую шлёт YooKassa (упрощённая под тест)."""
    return {
        "type": "notification",
        "event": event,
        "object": {
            "id": kassa_id,
            "status": "succeeded",
            "amount": {"value": amount, "currency": "RUB"},
            "metadata": {"payment_id": str(kp_id), "subscription_type": sub_type},
        },
    }

# payment.succeeded: синхронизируем платёж и создаём/обновляем активную подписку с сохранённым payment_method_id.
@pytest.mark.django_db
@override_settings(DJANGO_ENV="local")  # локально наш IP-чек пропускает вебхуки
def test_payment_succeeded_creates_subscription(client, monkeypatch):
    user = User.objects.create_user(email="u@test.io", password="x")
    kp = make_kp(user, kassa_id="p1", sub_type="monthly")

    # 1) пропускаем IP-чек (в реальной вьюхе он импортируется из payment.views)
    monkeypatch.setattr("payment.views.is_valid_webhook_signature", lambda req: True)

    # 2) мок YooKassa SDK на find_one: вернём объект с сохранённым способом оплаты
    fake_remote = SimpleNamespace(payment_method=SimpleNamespace(id="pm-1", saved=True), status="succeeded")
    monkeypatch.setattr("payment.hooks.KPayment.find_one", lambda _id: fake_remote)

    # 3) мок update_payment_status: помечаем платёж как успешный, имитируем то, что делает утилита
    def _stub_update(payment_id, remote):
        obj = KassaPayment.objects.get(kassa_payment_id=payment_id)
        obj.kassa_payment_status = "succeeded"
        obj.status = "completed"
        obj.income_amount = obj.amount
        obj.save(update_fields=["kassa_payment_status", "status", "income_amount", "updated_at"])
        return True
    monkeypatch.setattr("payment.hooks.update_payment_status", _stub_update)

    payload = webhook_payload("p1", kp.id, "monthly", amount="300.00")
    resp = client.post(WEBHOOK_URL, data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 200

    # Проверяем запись платежа
    kp.refresh_from_db()
    assert kp.kassa_payment_status == "succeeded"
    assert kp.status == "completed"

    # Создана/обновлена подписка
    sub = Subscription.objects.filter(user=user, plan="monthly", status="active").first()
    assert sub is not None
    assert sub.payment_method_id == "pm-1"
    assert sub.next_charge_at is not None

    # Записан журнал события
    log = PaymentEventLog.objects.filter(event_id="p1", event_type="payment.succeeded", applied=True).first()
    assert log is not None

# Идемпотентность: повторная доставка того же payment.succeeded не дублирует подписку, но журналирует оба события.
@pytest.mark.django_db
@override_settings(DJANGO_ENV="local")
def test_payment_succeeded_is_idempotent(client, monkeypatch):
    user = User.objects.create_user(email="u2@test.io", password="x")
    kp = make_kp(user, kassa_id="p2", sub_type="monthly")

    monkeypatch.setattr("payment.views.is_valid_webhook_signature", lambda req: True)
    fake_remote = SimpleNamespace(payment_method=SimpleNamespace(id="pm-2", saved=True), status="succeeded")
    monkeypatch.setattr("payment.hooks.KPayment.find_one", lambda _id: fake_remote)

    def _stub_update(payment_id, remote):
        obj = KassaPayment.objects.get(kassa_payment_id=payment_id)
        obj.kassa_payment_status = "succeeded"
        obj.status = "completed"
        obj.save(update_fields=["kassa_payment_status", "status", "updated_at"])
        return True
    monkeypatch.setattr("payment.hooks.update_payment_status", _stub_update)

    body = json.dumps(webhook_payload("p2", kp.id, "monthly"))

    # Первый раз
    assert client.post(WEBHOOK_URL, data=body, content_type="application/json").status_code == 200
    # Дубликат того же события
    assert client.post(WEBHOOK_URL, data=body, content_type="application/json").status_code == 200

    # Подписка одна (не размножилась)
    assert Subscription.objects.filter(user=user, plan="monthly").count() == 1
    # Журналы события есть на оба вызова
    assert PaymentEventLog.objects.filter(event_id="p2", event_type="payment.succeeded").count() == 2

# Прод-режим: вебхук отсекается по IP-чеку (403), запись в PaymentEventLog не создаётся.
@pytest.mark.django_db
@override_settings(DJANGO_ENV="prod")  # в прод-режиме IP-чек включён
def test_webhook_rejected_by_ip_check(client):
    # Без monkeypatch'а вебхук должен быть отрезан сразу по IP
    payload = {"type": "notification", "event": "payment.succeeded", "object": {"id": "x"}}
    resp = client.post(WEBHOOK_URL, data=json.dumps(payload), content_type="application/json")
    assert resp.status_code == 403
    # И в журнал его не пишем (лог пишется только после IP-чека)
    assert PaymentEventLog.objects.count() == 0

# Анти-даблклик: два быстрых POST на /process-kassa/ — второй получает 429, пока первый «в полёте».
@pytest.mark.django_db
@override_settings(DJANGO_ENV="local")
def test_process_kassa_antidoubleclick_returns_429(client, monkeypatch):
    """
    Анти-даблклик: два быстрых POST на /process-kassa/ → второй даёт 429.
    Мокаем YooKassa.Payment.create, чтобы первый вызов создал локальный pending-платёж.
    Аутентифицируемся сессией (SessionAuthentication в REST_FRAMEWORK включён).
    """
    user = User.objects.create_user(email="ad@test.io", password="x")
    client.force_login(user)

    # Мокаем ответ YooKassa.Payment.create
    class _Confirm: confirmation_url = "https://example/ok"
    fake_remote = SimpleNamespace(id=f"p-{uuid.uuid4()}", confirmation=_Confirm())
    monkeypatch.setattr("payment.views.Payment.create", lambda payload, idem: fake_remote)

    body = {"subscription_type": "monthly"}

    # 1-й запрос — OK, создаёт локальный pending+waiting_for_capture
    r1 = client.post("/api/payment/process-kassa/", data=json.dumps(body), content_type="application/json")
    assert r1.status_code == status.HTTP_200_OK
    assert "session_url" in r1.json()

    # 2-й запрос в тот же 90-секундный интервал — должен словить анти-даблклик
    r2 = client.post("/api/payment/process-kassa/", data=json.dumps(body), content_type="application/json")
    assert r2.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert "Платёж уже создаётся" in r2.json().get("error", "")

# Запрет дубля подписки: при уже активной подписке того же плана /process-kassa/ возвращает 409 + next_charge_at.
@pytest.mark.django_db
@override_settings(DJANGO_ENV="local")
def test_process_kassa_duplicate_active_subscription_returns_409(client, monkeypatch):
    """
    Повторная подписка: при активной подписке того же плана новый запуск даёт 409.
    """
    user = User.objects.create_user(email="dup@test.io", password="x")
    client.force_login(user)

    # Активная подписка с будущим next_charge_at
    sub = Subscription.objects.create(
        user=user, plan="yearly", status="active", amount=Decimal("2500.00"), currency="RUB"
    )
    sub.next_charge_at = timezone.now() + timezone.timedelta(days=30)
    sub.save(update_fields=["next_charge_at"])

    # Мокаем YooKassa.Payment.create (не должен вызваться, но пусть будет безопасно)
    class _Confirm: confirmation_url = "https://example/ok"
    fake_remote = SimpleNamespace(id=f"p-{uuid.uuid4()}", confirmation=_Confirm())
    monkeypatch.setattr("payment.views.Payment.create", lambda payload, idem: fake_remote)

    body = {"subscription_type": "yearly"}
    r = client.post("/api/payment/process-kassa/", data=json.dumps(body), content_type="application/json")
    assert r.status_code == status.HTTP_409_CONFLICT
    j = r.json()
    assert j.get("error") == "У вас уже есть активная подписка этого типа."
    assert j.get("plan") == "yearly"
    assert "next_charge_at" in j
