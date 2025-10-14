# payment/management/commands/charge_subscriptions.py
from django.core.management.base import BaseCommand
from django.utils import timezone
import json, hashlib, traceback
from django.db.models.functions import Now
from yookassa import Payment as KPayment
from payment.models import Subscription, KassaPayment
from payment.utils import create_receipt, create_payment_data, update_payment_status

class Command(BaseCommand):
    help = "Списание средств за подписку через сохраненный идентификатор метода оплаты (YooKassa)."

    def add_arguments(self, parser):
        parser.add_argument('--limit', type=int, default=100, help='Максимальное количество подписок на обработку за один запуск.')

    def handle(self, *args, **opts):
        now = timezone.now()

        base_qs = Subscription.objects.filter(
            status='active',
            next_charge_at__isnull=False,
        )
        due_qs = base_qs.filter(next_charge_at__lte=Now())

        self.stdout.write(
            f"[charge] now={now.isoformat()} base_count={base_qs.count()} due_count={due_qs.count()}"
        )

        for s in due_qs[:opts['limit']]:
            self.stdout.write(
                f"[charge] sub={s.id} user={s.user.email} plan={s.plan} "
                f"next={s.next_charge_at.isoformat()} pm_id={s.payment_method_id!r}"
            )

            if not s.payment_method_id:
                s.fails_count += 1
                if s.fails_count >= 3:
                    s.status = 'past_due'
                s.save(update_fields=['fails_count', 'status', 'updated_at'])
                continue

            payment = KassaPayment.objects.create(
                user=s.user,
                amount=s.amount,
                subscription_type=s.plan,
                coupon_code='',
                discount=0,
                status='pending',
                kassa_payment_status='waiting_for_capture',
                information_payment='Recurring charge',
            )

            receipt = create_receipt(s.user, s.plan, s.amount)
            payment_data = create_payment_data(
                amount=s.amount,
                description=f"Subscription {s.plan} renewal",
                local_payment_id=payment.id,
                subscription_type=s.plan,
                receipt=receipt,
                payment_method_id=s.payment_method_id,  # рекуррент: без confirmation, capture=true
            )

            payload_fingerprint = hashlib.sha1(
                json.dumps(payment_data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).hexdigest()[:12]
            due_key = (s.next_charge_at or now).isoformat()
            idem = f"sub:{s.id}:{due_key}:{payload_fingerprint}"

            try:
                remote = KPayment.create(payment_data, idem)
                # привязываем локальную запись к удалённому платежу
                payment.kassa_payment_id = remote.id
                payment.save(update_fields=['kassa_payment_id', 'updated_at'])
                s.last_payment_id = remote.id
                s.save(update_fields=['last_payment_id', 'updated_at'])

                # Если ЮKassa уже вернула status=succeeded — синхронизируем локально сразу
                if getattr(remote, "status", None) == "succeeded":
                    # обновим платёж (включая income_amount и пр.)
                    update_payment_status(remote.id, remote)

                    # сдвинем расписание подписки и обнулим фейлы
                    s.fails_count = 0
                    s.schedule_next()
                    s.save(update_fields=['fails_count', 'next_charge_at', 'updated_at'])

                    self.stdout.write(
                        self.style.SUCCESS(
                            f"[charge] sub={s.id} remote={remote.id} synced immediately (succeeded)"
                        )
                    )
                else:
                    # иначе дождёмся вебхуков (waiting_for_capture → succeeded)
                    self.stdout.write(f"[charge] sub={s.id} remote={remote.id} status={getattr(remote,'status',None)}")

            except Exception as e:
                self.stderr.write(f"[charge][ERROR] sub={s.id} {e}")
                traceback.print_exc()
                s.fails_count += 1
                if s.fails_count >= 3:
                    s.status = 'past_due'
                s.save(update_fields=['fails_count', 'status', 'updated_at'])

        self.stdout.write(self.style.SUCCESS(f"Processed: {min(due_qs.count(), opts['limit'])} subscription(s)."))
