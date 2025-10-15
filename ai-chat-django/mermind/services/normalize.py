# mermind/services/normalize.py
import re

MERMAID_HEADS = (
    "flowchart", "graph", "sequence", "state", "er", "class",
    "journey", "gantt", "timeline", "pie", "mindmap", "gitgraph", "quadrant",
)

def extract_fenced(text: str) -> str:
    if not text:
        return ""
    # ищем ```mermaid ... ```
    m = re.search(r"```(?:mermaid)?\s*([\s\S]*?)```", text, re.IGNORECASE)
    return (m.group(1).strip() if m else text.strip())

def looks_like_mermaid(code: str) -> bool:
    head = (code or "").strip().lower()
    return head.startswith(MERMAID_HEADS)


_BRAND_FIXES = [
    # любые варианты YandexPay/Yandex Pay → YooKassa
    (re.compile(r'\bYandex\s*Pay\b', re.IGNORECASE), "YooKassa"),
    (re.compile(r'\bYandexPay\b', re.IGNORECASE), "YooKassa"),
    # частые латинские варианты
    (re.compile(r'\bYo+ka?ssa\b', re.IGNORECASE), "YooKassa"),  # Yookassa/YoKassa/…
    # русские варианты в латинице/кириллице
    (re.compile(r'\bЮ\s*Касса\b', re.IGNORECASE), "ЮKassa"),
    (re.compile(r'\bЮкасса\b', re.IGNORECASE), "ЮKassa"),
]

def normalize_brand_names(code: str) -> str:
    s = code or ""
    for pat, repl in _BRAND_FIXES:
        s = pat.sub(repl, s)
    return s


def _to_mermaid_comment(line: str) -> str:
    # "# comment" -> "%% comment"
    s = line.lstrip()
    if s.startswith("#"):
        return "%% " + s[1:].lstrip()
    return line

def sanitize_mermaid(raw: str) -> str:
    """
    1) берём только fenced-содержимое (если есть),
    2) ждём первую строку с началом mermaid-диаграммы,
    3) отбрасываем markdown-fence и «болтовню» после кода,
    4) конвертируем `#`-комменты в `%%`.
    """
    s = extract_fenced(raw)
    lines = (s or "").splitlines()

    out, started = [], False
    preface_comments = []  # ← соберём %% до «головы»
    
    for ln in lines:
        stripped = ln.strip()

        # останов: закрывающая тройная косая
        if stripped.startswith("```"):
            break

        # стартуем только с первой валидной головы
        if not started:
            if stripped.lower().startswith(MERMAID_HEADS):
                started = True
                out.append(ln)
            else:
                # берём только валидные мермейд-комменты; '#' превратим ниже
                if stripped.startswith("%%") or stripped.startswith("#"):
                    preface_comments.append(_to_mermaid_comment(ln))                
            continue

        # внутри кода: чистим `#` → `%%`
        out.append(_to_mermaid_comment(ln))

    cleaned = "\n".join(out).strip() or s.strip()
    
        # если были шапочные комменты — аккуратно добавим их в самый конец
    if preface_comments and cleaned:
        cleaned = f"{cleaned}\n\n" + "\n".join(preface_comments)
        
    return cleaned
