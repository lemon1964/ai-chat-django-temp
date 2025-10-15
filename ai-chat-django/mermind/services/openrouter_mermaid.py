# mermind/services/openrouter_mermaid.py
import json
from chat_app.model_providers.openrouter.query import query_openrouter
from ..prompt_presets import CLASSIFIER_SYSTEM, DIAGRAM_TYPES, GEN_TEMPLATES
from .normalize import MERMAID_HEADS, extract_fenced, looks_like_mermaid, normalize_brand_names, sanitize_mermaid
from .model_pool import pick_next_model_after

def classify(text: str, lang: str = "ru", model: str | None = None) -> str:
    """
    Классифицирует тип диаграммы.
    """
    user = f"Определи тип диаграммы для описания:\n{text}\nВерни только JSON."
    out, _used_model = query_openrouter(
        prompt=user,
        model_id=model,
        language=lang,
        system_prompt=CLASSIFIER_SYSTEM,
        temperature=0.2,
    )
    try:
        data = json.loads(out)
        t = data.get("type", "").strip()
        return t if t in DIAGRAM_TYPES else "flowchart"
    except Exception:
        return "flowchart"


def _clean_or_template(code: str, t: str) -> str:
    c = extract_fenced(code)
    return c if looks_like_mermaid(c) else GEN_TEMPLATES.get(t, "flowchart TD\nA-->B")


def generate(text: str, prefer_type: str | None, lang="ru", model: str | None = None):
    t = prefer_type if prefer_type in MERMAID_HEADS else classify(text, lang, model)

    sys = (
        f"Скорректируй Mermaid {t} код.\n"
        f"Верни ТОЛЬКО код Mermaid (без Markdown и пояснений).\n"
        f"Отвечай на русском.\n"
        f"Добавь КОРОТКИЙ блок комментариев на русском с разметкой '%%' В КОНЦЕ кода, "
        f"одним непрерывным блоком (без вставки комментариев между линиями диаграммы)."
    )
    user = f"Описание:\n{text}\nСтартуй коротким рабочим шаблоном."

    out, used = query_openrouter(
        prompt=user,
        model_id=model,
        language=lang,
        system_prompt=sys,
        temperature=0.4,
    )
    code = sanitize_mermaid(_clean_or_template(out, t))
    code = normalize_brand_names(code)
    if looks_like_mermaid(code):
        return t, code, [], (used or model or "")

    # fallback по пулу (как и было)
    next_model = pick_next_model_after(used or model)
    if next_model:
        out2, used2 = query_openrouter(
            prompt=user,
            model_id=next_model,
            language=lang,
            system_prompt=sys,
            temperature=0.3,
        )
        code2 = sanitize_mermaid(_clean_or_template(out2, t))
        code2 = normalize_brand_names(code2)
        if looks_like_mermaid(code2):
            return t, code2, ["fallback_used"], (used2 or next_model)

    # крайний шаблон
    tpl = GEN_TEMPLATES.get(t, "flowchart TD\nA-->B")
    return t, normalize_brand_names(tpl), ["template_fallback"], (used or model or "")