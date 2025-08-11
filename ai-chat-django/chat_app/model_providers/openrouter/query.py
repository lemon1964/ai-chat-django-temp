# chat_app/model_providers/openrouter/query.py
import requests
from decouple import config
from django.core.cache import cache
from django.conf import settings
from .selector import get_top_models

OPENROUTER_API_KEY = config("OPENROUTER_API_KEY")
OPENROUTER_URL = config("OPENROUTER_API_URL")


def query_openrouter(
    prompt: str,
    model_id: str,
    language: str = "en",
    system_prompt: str = None,
    temperature: float = 0.7,
):
    print("prompt", prompt, "model_id", model_id)
    print(
        "language", language, "system_prompt", system_prompt, "temperature", temperature
    )
    """Обновлённая версия с поддержкой кастомных параметров"""
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": settings.FRONT_URL,
        "X-Title": "AI Chat Demo",
    }

    payload = {
        "model": model_id,
        "messages": [
            {
                "role": "system",
                "content": system_prompt or "You are a helpful assistant.",
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": temperature,
    }

    try:
        response = requests.post(
            OPENROUTER_URL, headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        return content, model_id

    except Exception as e:
        print(f"Ошибка запроса: {str(e)}")

        # Обновляем кэш моделей
        fresh_models = get_top_models()

        # Берём первую доступную модель
        fallback_model = fresh_models["text_models"][0]["model_id"]
        print("fallback_model", fallback_model)
        try:
            # Повторный запрос
            response = requests.post(
                OPENROUTER_URL,
                headers=headers,
                json={**payload, "model": fallback_model},
                timeout=30,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"], fallback_model

        except Exception as e:
            print(f"Вторая ошибка от fallback_model: {str(e)}")
            # Формируем сообщение в зависимости от языка
            error_msg = (
                "OpenRouter сейчас недоступен. Пожалуйста, попробуйте позже."
                if language == "ru"
                else "OpenRouter is currently unavailable. Please try again later."
            )
            return error_msg, None