# ai-chat-django/auth_app/urls.py
from django.urls import path, include
from .views import (
    CustomRegisterView,
    CustomVerifyEmailView,
    CustomTokenObtainPairView,
    CustomOAuthRegisterOrLoginView)

urlpatterns = [
    # Кастомная регистрация
    path('registration/verify-email/', CustomVerifyEmailView.as_view(), name='custom_verify_email'),    # Подтверждение email
    path('registration/', CustomRegisterView.as_view(), name='custom_register'),    # Регистрация
    path('custom/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Вход
    
    path('custom/oauth/register-or-login/', CustomOAuthRegisterOrLoginView.as_view(), name='oauth_register_or_login'),  # OAuth Google NextAuth

    # Стандартные JWT/авторизационные пути
    path('', include('dj_rest_auth.urls')),
]