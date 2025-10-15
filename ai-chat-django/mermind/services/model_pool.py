# mermind/services/model_pool.py
from __future__ import annotations
from typing import List, Optional
from django.core.cache import cache

# берём тот же селектор, что и фронт/чат
from chat_app.model_providers.openrouter.selector import get_top_models


POOL_CACHE_KEY = "mermind_model_pool_v1"
POOL_TTL_SEC = 60  # минутная «живучесть» списка

def _dedup_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out

def get_model_pool() -> List[str]:
    """
    Плоский пул из ~10 «живых» моделей (code + text), порядок стабильный.
    Кешируем, чтобы не дёргать OpenRouter на каждый вызов.
    """
    pool = cache.get(POOL_CACHE_KEY)
    if isinstance(pool, list) and pool:
        return pool

    top = get_top_models() or {}
    code = [m["model_id"] for m in top.get("code_models", [])]
    text = [m["model_id"] for m in top.get("text_models", [])]

    pool = _dedup_keep_order([*code, *text])
    cache.set(POOL_CACHE_KEY, pool, POOL_TTL_SEC)
    return pool

def pick_next_model_after(current_id: Optional[str]) -> Optional[str]:
    """
    Детерминированная «следующая» модель из пула.
    - если current_id нет в пуле / None — берём первую;
    - иначе — следующий индекс по кругу.
    """
    pool = get_model_pool()
    if not pool:
        return None
    if not current_id or current_id not in pool:
        return pool[0]
    i = pool.index(current_id)
    return pool[(i + 1) % len(pool)]
