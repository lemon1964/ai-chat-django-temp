# mermind/models.py
from django.db import models
from django.conf import settings


class Diagram(models.Model):
    TYPE_CHOICES = [
        ("flowchart", "flowchart"),
        ("sequence", "sequence"),
        ("state", "state"),
        ("er", "erDiagram"),
        ("class", "classDiagram"),
        ("journey", "journey"),
        ("gantt", "gantt"),
        ("timeline", "timeline"),
        ("pie", "pie"),
        ("mindmap", "mindmap"),
        ("gitGraph", "gitGraph"),
        ("quadrant", "quadrantChart"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="diagrams",
        db_index=True,
    )
    title = models.CharField(max_length=200, blank=True)
    source_text = models.TextField()                         # исходный промпт
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, db_index=True)
    code = models.TextField()                                # mermaid
    model_used = models.CharField(max_length=100, blank=True, default="")  # фактическая модель
    language = models.CharField(max_length=8, default="ru", db_index=True) # "ru" по умолчанию
    warnings = models.JSONField(default=list, blank=True)    # список строк-предупреждений
    tags = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-updated_at",)

    def __str__(self):
        return self.title or f"{self.type} #{self.pk}"


class DiagramRevision(models.Model):
    diagram = models.ForeignKey(
        Diagram, on_delete=models.CASCADE, related_name="revisions"
    )
    code = models.TextField()
    note = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at",)
