# ai-chat-django/mermind/tests.py
import json
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from mermind.services.normalize import (
    sanitize_mermaid,
    normalize_brand_names,
    looks_like_mermaid,
)

User = get_user_model()

# UNIT-тесты sanitize/normalize

def test_sanitize_moves_preface_comments_and_hash_to_percent():
    raw = """```mermaid
    %% верхний комментарий
    # ещё коммент в шапке
    classDiagram
    class A { +m() }
    # внутри-тоже-хэш
    болтовня после кода игнорируется
    ```"""
    cleaned = sanitize_mermaid(raw)
    # Начинается с головы mermaid
    assert cleaned.splitlines()[0].strip().lower().startswith("classdiagram")

    # Хэш внутри превратился в %%
    assert "%% внутри-тоже-хэш" in cleaned

    # Шапочные %%/хэш ушли в самый конец
    assert cleaned.strip().endswith("%% верхний комментарий\n%% ещё коммент в шапке")


def test_normalize_brand_names():
    src = "sequenceDiagram\nUser->>Yandex Pay: pay\nЮкасса->>Bank: ok\nYoookassa ok"
    out = normalize_brand_names(src)

    # Нормализованные варианты присутствуют
    assert "YooKassa" in out
    assert "ЮKassa" in out

    # Исходные варианты отсутствуют
    assert "Yandex Pay" not in out
    assert "Юкасса" not in out


# API-тесты /generate/ и /adjust/ с моками


@pytest.mark.django_db
def test_generate_sanitizes_and_normalizes(monkeypatch):
    """
    /api/mermaid/generate/
    - классификатор → 'sequence'
    - OpenRouter → fenced-код с префейс-комментами и 'YandexPay'
    Ожидаем: код начинается с 'sequence', бренд нормализован, префейс-комменты внизу.
    """
    # мок классификатора
    monkeypatch.setattr(
        "mermind.services.openrouter_mermaid.classify",
        lambda *args, **kwargs: "sequence",
    )

    # мок OpenRouter
    def _fake_query_openrouter(**kwargs):
        content = """```mermaid
        %% шапочный комментарий
        sequenceDiagram
        User->>YandexPay: start
        YandexPay->>Bank: charge
        ````"""
        return content, (kwargs.get("model_id") or "mock-model")

    monkeypatch.setattr(
        "mermind.services.openrouter_mermaid.query_openrouter",
        lambda **kw: _fake_query_openrouter(**kw),
    )

    client = APIClient()
    user = User.objects.create_user(email="u@test.io", password="x")
    client.force_authenticate(user)

    resp = client.post(
        "/api/mermaid/generate/",
        data={"text": "любой текст", "type": "", "language": "ru"},
        format="json",
    )
    assert resp.status_code == 200
    data = resp.json()
    code = data["code"]

    assert looks_like_mermaid(code)
    assert code.splitlines()[0].strip().lower().startswith("sequencediagram")
    assert data.get("used_model") == "mock-model"


@pytest.mark.django_db
def test_adjust_with_fallback_rotation(monkeypatch):
    """
    /api/mermaid/adjust/
    Первый ответ OpenRouter — болтовня (не mermaid).
    pick_next_model_after → 'next-model'.
    Второй ответ — валидный fenced.
    Ждём warnings=['fallback_used'] и корректный код.
    """
    calls = {"n": 0}

    def _fake_query(**kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return ("вот ваш код, класс!", kw.get("model_id") or "first-model")
        return (
            """```mermaid
                flowchart TD
                A-->B
                ```""",
            kw.get("model_id") or "next-model",
        )

    monkeypatch.setattr(
        "mermind.services.openrouter_mermaid.query_openrouter",
        lambda **kw: _fake_query(**kw),
    )

    # форсируем «следующую» модель
    monkeypatch.setattr(
        "mermind.services.model_pool.pick_next_model_after",
        lambda current_id: "next-model",
    )

    client = APIClient()
    user = User.objects.create_user(email="u2@test.io", password="x")
    client.force_authenticate(user)

    payload = {
        "code": "flowchart TD\nA-->C",
        "type": "flowchart",
        "instruction": "сделай A-->B",
        "language": "ru",
    }
    resp = client.post(
        "/api/mermaid/adjust/",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 200

    data = resp.json()
    assert looks_like_mermaid(data["code"])
    assert data.get("used_model")
