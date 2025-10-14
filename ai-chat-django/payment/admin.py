# payment/admin.py
from django.contrib import admin
from .models import KassaPayment, Coupon, Subscription, PaymentEventLog

@admin.register(KassaPayment)
class KassaPaymentAdmin(admin.ModelAdmin):
    list_display = (
        'user', 'subscription_type', 'amount',
        'status', 'kassa_payment_status',
        'kassa_payment_id',
        'created_at', 'updated_at',
    )
    readonly_fields = ('capture_idem_key',)
    search_fields = ('user__email', 'kassa_payment_id',)
    list_filter = ('status', 'subscription_type', 'kassa_payment_status')

@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ['code', 'discount', 'active', 'subscription_type', 'valid_from', 'valid_to']
    list_filter = ['active', 'valid_from', 'valid_to']
    search_fields = ['code']

@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('user','plan','status','amount','next_charge_at','fails_count','payment_method_id','last_payment_id','created_at')
    list_filter = ('plan','status')
    search_fields = ('user__email','payment_method_id','last_payment_id')
    
@admin.register(PaymentEventLog)
class PaymentEventLogAdmin(admin.ModelAdmin):
    list_display = ('received_at', 'event_type', 'event_id', 'applied')
    search_fields = ('event_id', 'event_type')
    list_filter = ('applied', 'event_type')
    readonly_fields = ('event_id','event_type','payload','received_at','applied','note')
