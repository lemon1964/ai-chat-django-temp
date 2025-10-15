# ai-chat-django/ai_chat_django/urls.py
from django.contrib import admin
from django.http import HttpResponse
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/auth/', include('auth_app.urls')),  # Все аутентификационные пути в auth_app
    path('accounts/', include('allauth.urls')),   # Системная почтовая верификация от allauth
    path('api/chat/', include('chat_app.urls')),  # Все чат-пути в chat_app 
    path("api/payment/", include("payment.urls")),  # API для платежного сервиса    
    path("api/mermaid/", include("mermind.urls")),  # API для Mermaid
    path('healthz/', lambda request: HttpResponse("Welcome to Django REST Module!")),   # проверка доступности
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
