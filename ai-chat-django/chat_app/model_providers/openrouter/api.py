# chat_app/model_providers/openrouter/api.py
import requests
from decouple import config

OPENROUTER_MODELS_URL = config("OPENROUTER_MODELS_URL")


def fetch_models() -> list[dict]:
    """Загружает все модели с OpenRouter."""
    response = requests.get(OPENROUTER_MODELS_URL, timeout=10)
    response.raise_for_status()
    return response.json().get("data", [])


def is_model_free(model: dict) -> bool:
    """Проверяет, что модель полностью бесплатна."""
    pricing = model.get("pricing", {})
    return all(
        float(pricing.get(key, 0)) == 0 for key in ("prompt", "completion", "request")
    )
