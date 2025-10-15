# mermind/views.py
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Q
from .serializers import DiagramSerializer, DiagramPatchSerializer
from .services.openrouter_mermaid import generate
from .services.normalize import extract_fenced, looks_like_mermaid, normalize_brand_names, sanitize_mermaid
from .services.model_pool import pick_next_model_after
from chat_app.model_providers.openrouter.query import query_openrouter
from .models import Diagram

import logging
logger = logging.getLogger("mermind")


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def generate_mermaid(request):
    """
    Вход: { text, type?, language?, model_id? }
    Выход: { type, code, warnings, used_model }
    - type опционально (подсказывает желаемый тип); если пусто — делаем классификацию
    - language по умолчанию "ru"
    - code всегда проходит sanitize/normalize (без Markdown-болтовни, c '%%' комментариями)
    """
    text = (request.data.get("text") or "").strip()
    prefer_type = (request.data.get("type") or "").strip()
    lang = request.data.get("language") or "ru"
    model_id = request.data.get("model_id") or request.data.get("model")

    if not text:
        return Response({"error": "empty text"}, status=400)

    try:
        t, code, warnings, used_model = generate(text, prefer_type, lang, model_id)

        # Доп. страховка: если не получили валидную «голову», считаем провайдера недоступным
        if not code.strip().lower().startswith(
            ("flowchart", "graph", "sequence", "state", "er",
             "class", "journey", "gantt", "timeline", "pie",
             "mindmap", "gitgraph", "quadrant")
        ):
            return Response({"error": "OpenRouter сейчас недоступен. Попробуйте позже."}, status=503)

        return Response(
            {"type": t, "code": code, "warnings": warnings, "used_model": used_model},
            status=200
        )
    except RuntimeError:
        return Response({"error": "OpenRouter сейчас недоступен. Попробуйте позже."}, status=503)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def save_diagram(request):
    """
    Создание/обновление диаграммы.
    Вход (минимум): { type, code, source_text }
    Опционально: { id, title, tags, model_used }
    - tags можно передавать массивом или строкой — приведём к "tag1, tag2"
    - language принудительно "ru" (для простоты)
    Выход: полная сущность диаграммы (через DiagramSerializer).
    """
    data = request.data.copy()
    data["language"] = "ru"

    # Нормализуем tags -> строка "a, b, c"
    tags = data.get("tags")
    if isinstance(tags, list):
        data["tags"] = ", ".join(str(t).strip() for t in tags if str(t).strip())
    elif isinstance(tags, str):
        data["tags"] = ", ".join(t.strip() for t in tags.split(",") if t.strip())
    else:
        data["tags"] = ""

    diagram_id = data.get("id")
    if diagram_id:
        obj = get_object_or_404(Diagram, pk=diagram_id, user=request.user)
        ser = DiagramSerializer(obj, data=data, partial=True)
    else:
        ser = DiagramSerializer(data=data)

    if ser.is_valid():
        instance = ser.save(user=request.user)
        return Response(DiagramSerializer(instance).data, status=200)

    # на время отладки — покажем причину 400
    return Response(ser.errors, status=400)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_diagrams(request):
    q = (request.GET.get("q") or "").strip()
    t = (request.GET.get("type") or "").strip()
    tags = (request.GET.get("tags") or "").strip()
    try:
        limit = int(request.GET.get("limit", 50))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    qs = Diagram.objects.filter(user=request.user)

    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(source_text__icontains=q))

    if t:
        qs = qs.filter(type=t)

    if tags:
        for tag in [s.strip() for s in tags.split(",") if s.strip()]:
            qs = qs.filter(tags__icontains=tag)

    qs = qs.order_by("-updated_at")[:limit]

    data = [
        {
            "id": d.id,
            "title": d.title,
            "source_text": d.source_text,
            "type": d.type,
            "tags": d.tags,
            "updated_at": d.updated_at,
            "model_used": d.model_used,
        }
        for d in qs
    ]
    return Response(data)

@api_view(["GET", "PATCH", "DELETE"])
@permission_classes([IsAuthenticated])
def diagram_detail(request, pk: int):
    obj = get_object_or_404(Diagram, pk=pk, user=request.user)

    if request.method == "GET":
        return Response(DiagramSerializer(obj).data)

    if request.method == "PATCH":
        ser = DiagramPatchSerializer(obj, data=request.data, partial=True)
        if ser.is_valid():
            ser.save()
            return Response(DiagramSerializer(obj).data, status=status.HTTP_200_OK)
        return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

    if request.method == "DELETE":
        obj.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def adjust_mermaid(request):
    """
    Итерируем код по инструкции:
    вход: { code, type, instruction, model_id? }
    выход: { type, code, used_model, warnings }
    """
    code = (request.data.get("code") or "").strip()
    t = request.data.get("type") or "flowchart"
    instr = (request.data.get("instruction") or "").strip()
    lang = "ru"
    model = request.data.get("model_id") or request.data.get("model")

    if not code or not instr:
        return Response({"error": "empty code or instruction"}, status=400)

    system = f"""
        Ты модифицируешь Mermaid {t} код.
        Верни ТОЛЬКО код Mermaid в тройных кавычках (fenced), без пояснений.
        Не добавляй Markdown, описания или текст вне кода.
        Комментарии внутри кода — только через '%%', строки с '#' не используй.
        """.strip()
    user = f"Инструкция:\n{instr}\n\nТекущий код:\n```mermaid\n{code}\n```"
    out, used = query_openrouter(prompt=user, model_id=model, language=lang, system_prompt=system, temperature=0.2)

    fixed = extract_fenced(out)
    fixed = sanitize_mermaid(out)
    fixed = normalize_brand_names(fixed)
    if looks_like_mermaid(fixed):
        return Response({"type": t, "code": fixed, "used_model": used, "warnings": []})

    # fallback -> ротация
    nm = pick_next_model_after(used or model)
    if nm:
        out2, used2 = query_openrouter(prompt=user, model_id=nm, language=lang, system_prompt=system, temperature=0.2)
        fixed2 = extract_fenced(out2)
        fixed2 = sanitize_mermaid(out2)
        fixed2 = normalize_brand_names(fixed2)
        if looks_like_mermaid(fixed2):
            return Response({"type": t, "code": fixed2, "used_model": used2, "warnings": ["fallback_used"]})

    # крайний случай — ничего не ломаем
    return Response({"type": t, "code": code, "used_model": used or model, "warnings": ["no_change"]})
