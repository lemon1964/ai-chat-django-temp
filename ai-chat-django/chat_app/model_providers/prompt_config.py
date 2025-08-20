# chat_app/model_providers/prompt_config.py

TEXT_DEFAULT_SYSTEMS = {
    "en": "You are a helpful AI assistant. Answer politely and informatively.",
    "ru": "Ты — полезный AI-ассистент. Отвечай вежливо и информативно.",
}

TEXT_TEMPERATURE = 0.7

CODE_DEFAULT_SYSTEMS = {
    "en": "You are an AI assistant for code generation. Write clear, concise code with explanations.",
    "ru": "Ты — AI-ассистент для генерации кода. Пиши понятный, краткий код с пояснениями.",
}

CODE_TEMPERATURE = 0.3

prompt_config = {
    "text": {
        "default_systems": TEXT_DEFAULT_SYSTEMS,
        "temperature": TEXT_TEMPERATURE,
    },
    "code": {
        "default_systems": CODE_DEFAULT_SYSTEMS,
        "temperature": CODE_TEMPERATURE,
    },
}
