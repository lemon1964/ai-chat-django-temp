# ai-chat-django/chat_app/types.py
from enum import Enum

class ModelType(str, Enum):
    """Классификация поддерживаемых типов AI-моделей"""
    TEXT = "text"    # Текстовые модели
    CODE = "code"    # Модели генерации кода