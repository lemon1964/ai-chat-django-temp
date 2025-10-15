# mermind/apps.py
from django.apps import AppConfig

class MermindConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "mermind"
    def ready(self):
        from . import signals  # noqa
