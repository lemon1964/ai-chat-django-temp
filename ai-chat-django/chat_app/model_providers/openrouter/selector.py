# chat_app/model_providers/openrouter/selector.py
from collections import defaultdict
from .api import fetch_models, is_model_free


def get_top_models() -> dict:
    """Возвращает модели с приоритетом code-моделей во второй половине."""
    models = fetch_models()
    free_models = [m for m in models if is_model_free(m)]

    # Группируем по брендам и сортируем
    brand_groups = defaultdict(list)
    for model in free_models:
        brand = model["id"].split("/")[0].lower()
        brand_groups[brand].append(model["id"])

    sorted_brands = sorted(brand_groups.items(), key=lambda x: len(x[1]), reverse=True)[
        :10
    ]  # Лимит 10 брендов

    # Делим пополам: code-модели берём из начала списка
    split_idx = len(sorted_brands) // 2
    code_brands = sorted_brands[:split_idx]  # Первая половина - код
    text_brands = sorted_brands[split_idx:]  # Вторая половина - текст

    return {
        "code_models": [{"brand": b, "model_id": ids[0]} for b, ids in code_brands],
        "text_models": [{"brand": b, "model_id": ids[0]} for b, ids in text_brands],
    }