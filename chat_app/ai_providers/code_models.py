# ai-chat-django/chat_app/ai_providers/code_models.py
import requests
from decouple import config
from typing import Tuple
from ai_chat_django import settings

OPENROUTER_API_KEY = config("OPENROUTER_API_KEY")
OPENROUTER_URL = config("OPENROUTER_API_URL")

def query_openrouter(
    prompt: str,
    model: str,
    language: str = "en",
    system_prompt: str = None
    ) -> Tuple[str, None]:
    """
    Базовый запрос к API с оптимизациями для генерации кода:
    - Пониженная temperature (0.3) для точности
    - Специализированные системные промпты
    - Поддержка мультиязычных пояснений
    """
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": settings.FRONT_URL,
        "X-Title": "AI Chat Demo"
    }

    default_systems = {
        "en": "You are an AI coding assistant. Provide clean, commented code.",
        "ru": "Ты — AI-ассистент для генерации кода. Предоставляй чистый код с комментариями."
    }
    system = system_prompt or default_systems.get(language, default_systems["en"])

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,  # Критично для генерации кода
        "max_tokens": 1024,
        "stop": ["</s>", "<|endoftext|>", "[DONE]"]
    }

    try:
        response = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=45)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"], None
    except Exception as e:
        error_msg = str(e)
        print("language", language)
        if "Not Found" in error_msg:  # Дополнительная проверка для других исключений
            if language == "ru":
                return "Эта модель сейчас недоступна на OpenRouter. Пожалуйста, выберите другую модель.", None
            return "This model is currently unavailable on OpenRouter. Please select another model.", None
        return f"[OpenRouter Error] {error_msg}", None


def query_llama3_coder(prompt: str, language: str = "en") -> Tuple[str, None]:
    """
    Оптимальный баланс между скоростью и качеством:
    - Подходит для базовых задач
    - Краткие пояснения логики
    """
    model_systems = {
        "en": "Generate code with a brief explanation of the logic.",
        "ru": "Генерируй код с кратким пояснением логики.",
    }
    return query_openrouter(
        prompt,
        model="meta-llama/llama-3.3-8b-instruct:free",
        language=language,
        system_prompt=model_systems.get(language),
    )

def query_deepseek_prover(prompt: str, language: str = "en") -> Tuple[str, None]:
    """
    Для сложных алгоритмов:
    - Пошаговые оптимизации
    - Детальные комментарии
    - Анализ эффективности
    """
    model_systems = {
        "en": "Generate optimized code with comments explaining each step.",
        "ru": "Генерируй код с оптимизациями и пояснениями.",
    }
    return query_openrouter(
        prompt,
        model="deepseek/deepseek-prover-v2:free",
        language=language,
        system_prompt=model_systems.get(language),
    )

def query_qwen3_coder(prompt: str, language: str = "en") -> Tuple[str, None]:
    """
    Для комплексных решений:
    - Развернутые пошаговые объяснения
    - Поддержка нескольких языков
    - Подробный анализ кода
    """
    model_systems = {
        "en": "Generate code with step-by-step explanations.",
        "ru": "Генерируй код с пошаговыми объяснениями."
    }
    return query_openrouter(
        prompt,
        model="qwen/qwen3-30b-a3b:free",
        language=language,
        system_prompt=model_systems.get(language)
    )