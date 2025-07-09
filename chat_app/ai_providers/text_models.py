# ai-chat-django/chat_app/ai_providers/text_models.py
import requests
from decouple import config
from typing import Tuple
from ai_chat_django import settings

OPENROUTER_API_KEY = config("OPENROUTER_API_KEY")
OPENROUTER_URL = config("OPENROUTER_API_URL")


# Общая функция для всех текстовых моделей
def query_openrouter(
    prompt: str,
    model: str,
    system_prompt: str = None,
    max_tokens: int = 1024,
    language: str = "en"
) -> Tuple[str, None]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": settings.FRONT_URL,
        "X-Title": "AI Chat Demo"
    }
    
    default_systems = {
        "en": "You are a helpful AI assistant. Answer politely and informatively.",
        "ru": "Ты — полезный AI-ассистент. Отвечай вежливо и информативно."
    }
    default_system = system_prompt or default_systems.get(language, default_systems["en"])
    
    messages = [
        {"role": "system", "content": system_prompt or default_system},
        {"role": "user", "content": prompt}
    ]
    
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": max_tokens,
        "stop": ["</s>", "<|endoftext|>", "[DONE]"]  # Универсальные стоп-слова
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


# Конкретные модели
def query_deepseek(prompt: str, language: str = "en") -> Tuple[str, None]:
    model_systems = {
        "en": "Answer as an expert across a wide range of topics.",
        "ru": "Отвечай как эксперт по широкому кругу вопросов."
    }
    return query_openrouter(
        prompt,
        model="deepseek/deepseek-r1-0528-qwen3-8b:free",
        language=language,
        system_prompt=model_systems.get(language)
    )


def query_mistral(prompt: str, language: str = "en") -> Tuple[str, None]:
    model_systems = {
        "en": "Answer concisely and to the point.",
        "ru": "Отвечай кратко и по делу."
    }
    return query_openrouter(
        prompt,
        model="mistralai/devstral-small:free",
        language=language,
        system_prompt=model_systems.get(language)
    )


def query_deephermes(prompt: str, language: str = "en") -> Tuple[str, None]:
    model_systems = {
        "en": "Answer in detail with a philosophical slant",
        "ru": "Отвечай развернуто с философским уклоном."
    }
    return query_openrouter(
        prompt,
        model="nousresearch/deephermes-3-mistral-24b-preview:free",
        language=language,
        system_prompt=model_systems.get(language)
    )