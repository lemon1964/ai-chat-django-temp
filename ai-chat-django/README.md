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

## 🌐 Продакшен

Хостинг: [Render](https://render.com)  
URL: [https://ai-chat-backend-YYYY.onrender.com](https://ai-chat-backend-YYYY.onrender.com/healthz/)

