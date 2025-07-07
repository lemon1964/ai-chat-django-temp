# ai-chat-django/auth_app/serializers.py
from dj_rest_auth.registration.serializers import RegisterSerializer
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from ai_chat_django import settings

User = get_user_model()


class CustomRegisterSerializer(RegisterSerializer):
    name = serializers.CharField(required=True)
    provider = serializers.CharField(required=False, default='credentials')

    def save(self, request):    # переопределение метода save
        user = super().save(request)    # сохраняем пользователя
        user.name = self.validated_data['name']     # добавляем поле name
        user.provider = self.validated_data.get('provider', 'credentials')  # добавляем поле provider
        user.is_active = False  # устанавливаем is_active в False
        user.save()     # сохраняем изменения

        uid = urlsafe_base64_encode(force_bytes(user.pk))    # генерируем uid
        token = default_token_generator.make_token(user)    # генерируем токен
        confirmation_url = f"http://{settings.DOMAIN}{reverse('custom_verify_email')}?uid={uid}&token={token}"  # генерируем ссылку

        subject = "Email Confirmation"  # тема письма
        message = fr"Подтвердите свой адрес электронной почты, перейдя по следующей ссылке: {confirmation_url}"
        html_message = fr"""
        <html>
            <body>
                <p>Подтвердите свой адрес электронной почты, перейдя по следующей ссылке:</p>
                <p><a href="{confirmation_url}">Нажмите здесь для подтверждения адреса</a></p>
            </body>
        </html>
        """

        send_mail(  # отправляем письмо
            subject,
            message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_message,
        )

        return user

    
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):               # Добавляем поля в токен
        token = super().get_token(user)     # Получаем токен
        token['email'] = user.email
        token['name'] = user.name
        token['provider'] = user.provider
        return token

    def validate(self, attrs):              # Проверяем email и пароль
        credentials = {
            'email': attrs.get('email'),
            'password': attrs.get('password')
        }
        return super().validate(credentials)
    

class OAuthUserSerializer(serializers.Serializer):
    id = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    name = serializers.CharField(required=True)
    provider = serializers.CharField(required=True)

    def validate_provider(self, value):
        allowed_providers = ['google', 'facebook', 'github']  # Разрешенные провайдеры
        if value not in allowed_providers:
            raise serializers.ValidationError(f"Provider {value} is not supported.")
        return value