# chat_app/utils.py
from django.core.cache import cache
from .model_providers.openrouter.query import query_openrouter
from .model_providers.prompt_config import prompt_config

def query_provider(prompt: str, model_type: str, model_id: str, language: str = "en"):
    """Возвращает: (content, tokens_used, real_used_model)"""
    cache_key = f"{model_type}_{model_id}_{language}_{hash(prompt)}"
    if cached := cache.get(cache_key):
        return cached[0], cached[1], cached[2]

    config = prompt_config.get(model_type, prompt_config["text"])
    system_prompt = config["default_systems"].get(language, config["default_systems"]["en"])
    
    content, used_model = query_openrouter(
        prompt=prompt,
        model_id=model_id,
        language=language,
        system_prompt=system_prompt,
        temperature=config["temperature"]
    )
    
    tokens_used = len(content) // 4 if content else 0
    cache.set(cache_key, (content, tokens_used, used_model), timeout=3600)
    return content, tokens_used, used_model
