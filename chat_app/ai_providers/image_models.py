# ai-chat-django/chat_app/ai_providers/image_models.py
from typing import Tuple
import requests
from decouple import config
import base64
import uuid
import os
import time
from django.conf import settings
from django.core.files.base import ContentFile
import cloudinary.uploader
from ..models import GeneratedImage

TOGETHER_API_KEY = config("TOGETHER_API_KEY")
TOGETHER_API_URL = config("TOGETHER_API_URL")

# Глобальная переменная для rate limiting
LAST_REQUEST_TIME = 0

def query_flux_image(prompt: str) -> Tuple[str, None]:
    """Основная функция генерации изображений"""
    global LAST_REQUEST_TIME
    
    try:
        # Rate limiting (6 запросов в минуту)
        current_time = time.time()
        if current_time - LAST_REQUEST_TIME < 10:
            wait_time = 10 - (current_time - LAST_REQUEST_TIME)
            time.sleep(wait_time)
        
        # Формирование запроса
        headers = {"Authorization": f"Bearer {TOGETHER_API_KEY}"}
        payload = {
            "model": "black-forest-labs/FLUX.1-schnell-Free",
            "prompt": prompt,
            "width": 512,
            "height": 512,
            "steps": 4,
            "seed": int(time.time())
        }

        response = requests.post(TOGETHER_API_URL, headers=headers, json=payload, timeout=90)
        LAST_REQUEST_TIME = time.time()

        # Обработка ответа
        if response.status_code == 200:
            data = response.json()
            if "data" in data and len(data["data"]) > 0:
                image_data = data["data"][0]
                
                if "url" in image_data:
                    return _process_image_url(image_data["url"], prompt)
                elif "b64_json" in image_data:
                    return _process_base64(image_data["b64_json"], prompt)
        
        return "[Error] Invalid response format", None

    except Exception as e:
        return f"[Error] {str(e)}", None

def _process_image_url(url: str, prompt: str) -> Tuple[str, None]:
    """Обработка URL изображения"""
    try:
        img_response = requests.get(url, timeout=90)
        img_response.raise_for_status()
        
        upload_result = cloudinary.uploader.upload(
            img_response.content,
            folder="generated-images",
            public_id=str(uuid.uuid4())
        )
        
        img = GeneratedImage(
            prompt=prompt,
            source_url=url,
            url=upload_result["secure_url"]
        )
        img.save()
        
        return upload_result["secure_url"], None
        
    except Exception as e:
        return f"[Error] URL processing failed: {str(e)}", None

def _process_base64(b64_data: str, prompt: str) -> Tuple[str, None]:
    """Обработка base64 изображения"""
    try:
        img = GeneratedImage(prompt=prompt)
        img.file.save(
            f"{uuid.uuid4()}.png",
            ContentFile(base64.b64decode(b64_data)),
            save=True
        )
        return img.file.url, None
    except Exception as e:
        return f"[Error] Base64 processing failed: {str(e)}", None