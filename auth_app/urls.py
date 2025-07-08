# ai-chat-django/auth_app/urls.py
from django.urls import path, include
from rest_framework_simplejwt.views import TokenVerifyView
from .views import (
    CustomRegisterView,
    CustomVerifyEmailView,
    CustomTokenObtainPairView,
    CustomOAuthRegisterOrLoginView,
    CustomPasswordResetView,
    CustomPasswordResetConfirmView,
    RefreshTokenView,
    DeleteUserView)
from .views import get_user_data, update_name, update_quantity

urlpatterns = [
    # Кастомные регистрация, вход и подтверждение
    path('registration/verify-email/', CustomVerifyEmailView.as_view(), name='custom_verify_email'),    # Подтверждение email
    path('registration/', CustomRegisterView.as_view(), name='custom_register'),    # Регистрация
    path('custom/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Вход
    
    # OAuth Google
    path('custom/oauth/register-or-login/', CustomOAuthRegisterOrLoginView.as_view(), name='oauth_register_or_login'),  # OAuth Google NextAuth

    # Сброс пароля
    path('password/reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password/reset/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # JWT
    path("refresh/", RefreshTokenView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    
    # Удаление по id или email
    path('delete-user/', DeleteUserView.as_view(), name='delete_user_by_email_or_id'),
    
    # API пользователя    
    path('get-user-data/', get_user_data, name='get-user-data'),        # Данные о пользователе 
    path('update-name/', update_name, name='update-name'),              # Обновление имени
    path('update-quantity/', update_quantity, name='update-quantity'),  # Количество вопросов
    
    # Стандартные JWT/авторизационные пути, должны быть последними
    path('', include('dj_rest_auth.urls')),
]