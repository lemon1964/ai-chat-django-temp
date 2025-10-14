# chat_app/model_providers/openrouter/selector.py
from collections import defaultdict
from .api import fetch_models, is_model_free

BAD_HINTS = ("-coder", "vl-", "vl_", "vision")  # лёгкая зачистка «подозрительных» id

def get_top_models() -> dict:
    """Берём последние (предположительно свежие) free-модели по каждому бренду."""
    models = fetch_models()
    free_models = [m for m in models if is_model_free(m)]

    brand_groups = defaultdict(list)
    for m in free_models:
        mid = m["id"]
        brand = mid.split("/")[0].lower()     # ← бренд снова корректный
        brand_groups[brand].append(mid)       # порядок сохраняем как на витрине

    # Берём ТОП-10 брендов по числу моделей (как было)
    top = sorted(brand_groups.items(), key=lambda x: len(x[1]), reverse=True)[:10]

    # Для каждого бренда выбираем ПОСЛЕДНЮЮ free-модель (часто самая «живая»)
    def pick_latest(ids: list[str]) -> str:
        # берём с конца первый id, который не похож на code/vl/vision (очень лёгкий фильтр)
        for mid in reversed(ids):
            low = mid.lower()
            if not any(h in low for h in BAD_HINTS):
                return mid
        return ids[-1]  # fallback — самый последний

    # Разделение на text/code: половина брендов под code, половина под text (условно)
    split_idx = max(1, len(top) // 2)
    code_brands = top[:split_idx]
    text_brands = top[split_idx:]

    return {
        "code_models": [{"brand": b, "model_id": pick_latest(ids)} for b, ids in code_brands],
        "text_models": [{"brand": b, "model_id": pick_latest(ids)} for b, ids in text_brands],
    }