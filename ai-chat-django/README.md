# AI Chat — backend (Django + DRF)

Бэкенд для AI-чата. Обеспечивает:

- Авторизацию ( + OAuth -/- NextAuth)
- Подключение AI-моделей
- Обмен сообщениями
- Логику fallback
- API для фронта

## 🔗 Связан с фронтом

Репозиторий: [ai-chat-next](https://github.com/ВАШ_ЮЗЕРНЕЙМ/ai-chat-next)  
Продакшен: https://ai-chat-backend-YYYY.onrender.com/

## ⚙️ Стэк

- [Django 5](https://www.djangoproject.com/)
- [Django REST Framework](https://www.django-rest-framework.org/)
- [SQLite](https://www.sqlite.org/index.html)
- [gunicorn](https://gunicorn.org/)

## 🚀 Установка

```bash
git clone https://github.com/ВАШ_ЮЗЕРНЕЙМ/ai-chat-django.git
cd ai-chat-django
pip install -r requirements.txt
```

## 🧪 Запуск в dev-режиме

```bash
python3 manage.py migrate
python3 manage.py runserver
```

Откройте [http://localhost:8000](http://localhost:8000)

## ✨ Возможности

* REST API для чата (маршруты чата + fallback моделей)
* **MerMind API**: генерация/уточнение/сохранение диаграмм Mermaid
* **YooKassa**: оплата подписки, расчёт лимитов, уведомления (webhook)
* Флаги пользователя (гость/free/premium) и дневные лимиты для фронта

## 🔌 Основные эндпоинты

* Здоровье сервиса: `GET /healthz/`
* **Флаги и лимиты**: `GET /api/auth/me/flags/`
* **MerMind**

  * `POST /api/mermaid/generate/` — сгенерировать Mermaid-код
  * `POST /api/mermaid/adjust/` — уточнить существующий код
  * `POST /api/mermaid/save/` — сохранить диаграмму
  * `GET /api/mermaid/list/` — список диаграмм
  * `GET /api/mermaid/:id/` + `PATCH /api/mermaid/:id/` + `DELETE /api/mermaid/:id/`
* **YooKassa**

  * `POST /api/payment/create/` — создать платёж
  * `POST /api/payment/webhook/` — уведомления YooKassa
  * `GET /api/auth/me/flags/` — актуальные лимиты/тариф (для фронта)

## 🔐 Переменные окружения (бэк)

Render → Backend → Environment:

```
DJANGO_ENV=prod
DEBUG=false
DJANGO_SECRET_KEY=...

# Внешние API
OPENROUTER_API_URL=https://openrouter.ai/api/v1/chat/completions
OPENROUTER_API_KEY=...
TOGETHER_API_URL=https://api.together.ai/v1/images/generations
TOGETHER_API_KEY=...

# Cloudinary (если храните медиа/превью)
CLOUDINARY_CLOUD_NAME=...
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...
CLOUDINARY_URL=...

# YooKassa
SHOP_ID=...
KASSA_SECRET_KEY=...

# Прочее
CRON_SECRET=...

# Прод-домены
ALLOWED_HOSTS=ai-chat-backend-YYYY.onrender.com
CORS_ALLOWED_ORIGINS=https://ai-chat-frontend-XXXX.onrender.com
CSRF_TRUSTED_ORIGINS=https://ai-chat-frontend-XXXX.onrender.com

# Ссылки для фронта (в settings.py)
FRONT_URL=https://ai-chat-frontend-XXXX.onrender.com
DOMAIN=ai-chat-backend-YYYY.onrender.com
```

## 🌐 Продакшен

Хостинг: [Render](https://render.com)  
URL: [https://ai-chat-backend-YYYY.onrender.com](https://ai-chat-backend-YYYY.onrender.com/healthz/)

