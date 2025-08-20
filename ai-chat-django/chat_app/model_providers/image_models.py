# testing/ai-chat-django/chat_app/model_providers/image_models.py
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

# Глобальная переменная для отслеживания времени последнего запроса
LAST_REQUEST_TIME = 0


def query_flux_image(prompt: str) -> Tuple[str, None]:
    """Генерация изображений через Together.ai API с обработкой лимитов"""
    global LAST_REQUEST_TIME

    try:
        # Соблюдаем лимит в 6 запросов в минуту (10 секунд между запросами)
        current_time = time.time()
        if current_time - LAST_REQUEST_TIME < 10:
            wait_time = 10 - (current_time - LAST_REQUEST_TIME)
            print(f"Waiting {wait_time:.1f} seconds to comply with rate limits...")
            time.sleep(wait_time)

        headers = {
            "Authorization": f"Bearer {TOGETHER_API_KEY}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": "black-forest-labs/FLUX.1-schnell-Free",
            "prompt": prompt,
            "width": 512,
            "height": 512,
            "steps": 4,
            "seed": int(time.time()),  # Динамический seed для разнообразия
        }

        response = requests.post(
            TOGETHER_API_URL, headers=headers, json=payload, timeout=90
        )

        LAST_REQUEST_TIME = time.time()  # Обновляем время последнего запроса

        print("API response:", response.status_code, response.text)

        # Обработка успешного ответа
        if response.status_code == 200:
            data = response.json()
            if "data" in data and len(data["data"]) > 0:
                image_data = data["data"][0]

                if "url" in image_data:
                    img_response = requests.get(image_data["url"], timeout=90)

                    # img_response = requests.get(image_data["url"])
                    img_response.raise_for_status()

                    # 1) загружаем в Cloudinary
                    upload_result = cloudinary.uploader.upload(
                        img_response.content,
                        folder="generated-FLUX-schnell",  # опционально, чтобы сгруппировать
                        public_id=str(uuid.uuid4()),
                        resource_type="image",
                    )
                    secure_url = upload_result.get("secure_url")

                    # 2) сохраняем в модели и возвращаем URL
                    img = GeneratedImage(prompt=prompt, source_url=image_data["url"])
                    # мы НЕ используем img.file.save — просто сохраняем URL
                    img.url = secure_url  # вместо img.file
                    img.save()
                    return secure_url, None
                
                elif "b64_json" in image_data:
                    # Обработка base64
                    img = GeneratedImage(prompt=prompt)
                    img.file.save(
                        f"{uuid.uuid4()}.png",
                        ContentFile(base64.b64decode(image_data["b64_json"])),
                        save=True,
                    )
                    return img.file.url, None

        # Обработка ошибки 429
        elif response.status_code == 429:
            retry_after = int(response.headers.get("retry-after", 10))
            print(f"Rate limit exceeded. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            return query_flux_image(prompt)  # Рекурсивный повтор

        return "[Image Error] No valid image data in response", None

    except requests.exceptions.RequestException as e:
        print(f"Request error: {str(e)}")
        return f"[Image Error] Request failed: {str(e)}", None
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return f"[Image Error] {str(e)}", None
