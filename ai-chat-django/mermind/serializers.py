# mermind/serializers.py
from rest_framework import serializers
from .models import Diagram, DiagramRevision

class DiagramRevisionSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiagramRevision
        fields = ("id", "code", "note", "created_at")

class DiagramSerializer(serializers.ModelSerializer):
    revisions = DiagramRevisionSerializer(many=True, read_only=True)

    class Meta:
        model = Diagram
        fields = (
            "id", "title", "source_text", "type", "code",
            "model_used", "language", "warnings", "tags",
            "created_at", "updated_at", "revisions",
        )
        read_only_fields = ("created_at", "updated_at", "revisions")


class DiagramPatchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Diagram
        fields = ("title", "tags")
