# ai-chat-django/auth_app/views.py
from dj_rest_auth.registration.views import RegisterView
from .serializers import CustomRegisterSerializer

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect
from allauth.account.models import EmailAddress
from django.contrib.auth import get_user_model

from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from .serializers import CustomTokenObtainPairSerializer

from .serializers import OAuthUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from ai_chat_django import settings

User = get_user_model()

class CustomRegisterView(RegisterView):
    serializer_class = CustomRegisterSerializer

    def perform_create(self, serializer):    # переопределение метода perform_create
        user = serializer.save(self.request)    # сохраняем пользователя
        return user

    
class CustomVerifyEmailView(APIView):
    permission_classes = [AllowAny]  # доступ разрешён без токена

    def get(self, request, *args, **kwargs):    # переопределение метода get
        uid = request.GET.get("uid")            # получаем uid
        token = request.GET.get("token")        # получаем токен

        try:
            uid = urlsafe_base64_decode(uid).decode()   # декодируем uid
            user = User.objects.get(pk=uid)             # получаем пользователя
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "Invalid link."}, status=400)

        if default_token_generator.check_token(user, token):    # проверяем токен
            if not user.is_active:
                user.is_active = True                       # устанавливаем is_active в True
                user.save()                                 # сохраняем изменения

                # Отметим email как подтверждённый
                email_address = EmailAddress.objects.get(user=user)
                email_address.verified = True
                email_address.save()

                return redirect(f"{settings.FRONT_URL}/verification-success")
            else:
                return Response({"message": "User is already activated."}, status=200)
        else:
            return Response({"error": "Invalid or expired token."}, status=400)
        
        

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    # permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        """
        Переопределяем метод post, чтобы добавить проверку подтверждения email.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Получаем пользователя из данных сериализатора
        user = serializer.user
        
        # Проверяем подтверждение email
        email_address = EmailAddress.objects.filter(user=user, email=user.email).first()
        if not email_address or not email_address.verified:
            raise AuthenticationFailed(detail="Email address is not verified.")

        # Если email подтвержден, формируем токены
        token = serializer.validated_data['access']
        # print("token:", token)
        
        # Формируем данные пользователя
        user_data = {
            "email": user.email,
            "name": user.name,
            "id": user.id
        }
        
        # Возвращаем токены и данные пользователя
        return Response({
            'access': token,
            'refresh': serializer.validated_data['refresh'],
            'user': user_data  # Возвращаем данные пользователя
        }, status=status.HTTP_200_OK)
        

class CustomOAuthRegisterOrLoginView(APIView):
    permission_classes = [AllowAny]  # Разрешаем доступ без токена

    def post(self, request, *args, **kwargs):
        """
        Регистрирует или авторизует пользователя через OAuth с использованием сериалайзера.
        """        
        serializer = OAuthUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        provider = data['provider']
        email = data['email']
        name = data['name']
        user_id = data['id']

        try:
            # Проверяем, есть ли пользователь с таким email
            user, created = User.objects.get_or_create(email=email, defaults={
                'name': name,
                'provider': provider,
                'username': user_id,  # Используем id как уникальное имя пользователя
            })

            if created:
                print(f"default user created with newsletter=True")
            else:
                # Если пользователь уже существует, обновляем только провайдера и имя
                user.name = name
                user.provider = provider
                user.save()
                print(f"Existing user updated with provider={provider}")

            # Генерация токенов
            refresh = RefreshToken.for_user(user)
            access = str(refresh.access_token)

            return Response({
                'message': 'User successfully synchronized.',
                'user': {
                    'email': user.email,
                    'name': user.name,
                    'provider': user.provider,
                },
                'access': access,
                'refresh': str(refresh),
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error occurred: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)