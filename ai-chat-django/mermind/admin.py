# mermind/admin.py
from django.contrib import admin
from .models import Diagram, DiagramRevision

@admin.register(Diagram)
class DiagramAdmin(admin.ModelAdmin):
    list_display = ("short_title", "type", "model_used", "user", "updated_at")
    list_filter = ("type", "language", "model_used", "updated_at")
    search_fields = ("title", "source_text", "code", "user__email")
    readonly_fields = ("created_at", "updated_at")
    date_hierarchy = "updated_at"

    def short_title(self, obj):
        t = obj.title or obj.source_text
        return (t[:50] + "…") if t and len(t) > 50 else t
    short_title.short_description = "Title / Source"

@admin.register(DiagramRevision)
class DiagramRevisionAdmin(admin.ModelAdmin):
    list_display = ("diagram", "short_note", "created_at")
    search_fields = ("diagram__title", "note")
    date_hierarchy = "created_at"

    def short_note(self, obj):
        return obj.note or ""
