# payment/models.py
from django.db import models
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
from django.contrib.auth import get_user_model

User = get_user_model()
  
class KassaPayment(models.Model):
    user = models.ForeignKey(User, related_name='kassa_payments', on_delete=models.CASCADE)
    kassa_payment_id = models.CharField(max_length=250, blank=True, null=True)
    information_payment = models.CharField(max_length=250, blank=True, null=True) # Разная информация о платеже
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    subscription_type = models.CharField(choices=[('monthly', 'Monthly'), ('yearly', 'Yearly'), ('forever', 'Forever')], max_length=10)
    coupon_code = models.CharField(max_length=50, blank=True, null=True)
    discount = models.IntegerField(default=0)  # Используем IntegerField вместо DecimalField
    status = models.CharField(choices=[('pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed'), ('refund', 'Refund'), ('refund_failed', 'Refund Failed')], max_length=20, default='pending')    
    kassa_payment_status = models.CharField(
        choices=[('waiting_for_capture', 'Waiting for capture'), 
                ('succeeded', 'Succeeded'), 
                ('failed', 'Failed'),
                ('canceled', 'Canceled'),
                ('refund_succeeded', 'Refund Succeeded')],
    max_length=20, 
    default='waiting_for_capture'
)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    expires_at = models.DateTimeField(blank=True, null=True)
    authorization_details = models.JSONField(blank=True, null=True)  # Чтобы хранить детализированные данные о 3D Secure
    payment_method = models.JSONField(blank=True, null=True)  # Чтобы хранить информацию о способе оплаты (карта, кошелек и т.д.)
    income_amount = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)  # Сумма после вычета комиссии
    capture_idem_key = models.CharField(max_length=64, blank=True, null=True)  # стабильный ключ идемпотентности для capture
    def __str__(self):
        return f"{self.user.username} - {self.subscription_type} - {self.status} - {self.kassa_payment_status}"



class Coupon(models.Model):
    code = models.CharField(max_length=50, unique=True)  # Код купона
    discount = models.DecimalField(max_digits=5, decimal_places=2)  # Процент скидки
    valid_from = models.DateTimeField()  # Дата начала действия
    valid_to = models.DateTimeField()  # Дата окончания действия
    active = models.BooleanField(default=True)  # Статус купона (активен/неактивен)
    subscription_type = models.CharField(
        choices=[('monthly', 'Monthly'), ('yearly', 'Yearly'), ('forever', 'Forever')],
        max_length=10,
        blank=True, null=True
    )  # Тип подписки, для которой действует купон
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Coupon {self.code} - {self.discount}% for {self.subscription_type}"

    def is_valid(self):
        """Проверка на срок действия купона"""
        now = timezone.now()
        return self.active and self.valid_from <= now <= self.valid_to
    
    def apply_to_subscription(self, subscription_type):
        """Проверка применимости купона к типу подписки"""
        if self.subscription_type:
            return self.subscription_type == subscription_type
        return True  # Если купон для всех подписок
    

class Subscription(models.Model):
    PLAN_CHOICES = (
        ('monthly', 'Monthly'),
        ('yearly', 'Yearly'),
    )
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('canceled', 'Canceled'),
        ('paused', 'Paused'),
    )

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.CharField(max_length=16, choices=PLAN_CHOICES)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='active')

    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    currency = models.CharField(max_length=3, default='RUB')

    payment_method_id = models.CharField(max_length=128, blank=True, null=True)
    last_payment_id = models.CharField(max_length=64, blank=True, null=True)

    next_charge_at = models.DateTimeField(blank=True, null=True)
    fails_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def schedule_next(self):
        # для локальных тестов можно временно сделать +10 минут
        if self.plan == 'monthly':
            self.next_charge_at = timezone.now() + timedelta(days=30)
        else:  # yearly
            self.next_charge_at = timezone.now() + timedelta(days=365)

    def __str__(self):
        return f"{self.user.email} {self.plan} ({self.status})"


class PaymentEventLog(models.Model):
    event_id = models.CharField(max_length=64, db_index=True)      # id платежа/возврата из payload.object.id
    event_type = models.CharField(max_length=64, db_index=True)    # payment.succeeded / payment.canceled / …
    payload = models.JSONField()                                   # сырой JSON вебхука
    received_at = models.DateTimeField(auto_now_add=True)          # когда получили
    applied = models.BooleanField(default=False)                   # удалось применить (обновили БД) — да/нет
    note = models.TextField(blank=True, null=True)                 # причина, если не применён

    class Meta:
        ordering = ('-received_at',)

    def __str__(self):
        return f"{self.event_type} {self.event_id} ({'applied' if self.applied else 'pending'})"
