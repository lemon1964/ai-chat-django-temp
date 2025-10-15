# mermind/signals.py
from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from .models import Diagram, DiagramRevision

@receiver(post_save, sender=Diagram)
def create_initial_revision(sender, instance: Diagram, created, **kwargs):
    if created and instance.code:
        DiagramRevision.objects.create(diagram=instance, code=instance.code, note="initial")

@receiver(pre_save, sender=Diagram)
def add_revision_on_change(sender, instance: Diagram, **kwargs):
    if not instance.pk:
        return
    try:
        old = Diagram.objects.get(pk=instance.pk)
    except Diagram.DoesNotExist:
        return
    if old.code != instance.code:
        # ревизию создадим после сохранения нового кода
        instance._needs_revision_from = old.code

@receiver(post_save, sender=Diagram)
def finalize_revision(sender, instance: Diagram, created, **kwargs):
    if getattr(instance, "_needs_revision_from", None) is not None:
        DiagramRevision.objects.create(diagram=instance, code=instance.code, note="update")
        instance._needs_revision_from = None
