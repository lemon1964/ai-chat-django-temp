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

from django.http import HttpResponseRedirect
from dj_rest_auth.views import PasswordResetView
from .serializers import CustomPasswordResetSerializer

from rest_framework_simplejwt.tokens import BlacklistedToken, TokenError
           
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

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
        

class CustomPasswordResetView(PasswordResetView):
    serializer_class = CustomPasswordResetSerializer
    def get_serializer_context(self):
        """
        Добавляет в контекст объект запроса (request).
        UID и token автоматически обрабатываются в CustomPasswordResetSerializer.
        """
        context = super().get_serializer_context()
        # Добавляем request в контекст для использования в CustomPasswordResetSerializer
        context.update({"request": self.request})
        return context
    

class CustomPasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]  # Разрешаем доступ без токена

    def get(self, request, uidb64, token, *args, **kwargs):
        # Формируем URL для фронтенда
        frontend_url = f"{settings.FRONT_URL}/auth/password-reset/{uidb64}/{token}/"
        return HttpResponseRedirect(frontend_url)
    
    
class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")     # Данные из тела запроса

        if not refresh_token:
            return Response(
                {"detail": "Refresh token is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)         # Создаем токен

            # Проверка, находится ли токен в черном списке
            if BlacklistedToken.objects.filter(token__jti=token['jti']).exists():
                raise AuthenticationFailed(detail="Token has been blacklisted.")

            new_access_token = str(token.access_token)   # Создаем новый токен

            return Response(
                {
                    "accessToken": new_access_token,
                    "refreshToken": refresh_token,
                },
                status=status.HTTP_200_OK,
            )
        except TokenError as e:
            raise AuthenticationFailed(
                detail="Invalid or expired refresh token."
            ) from e
            
            
class DeleteUserView(APIView):
    permission_classes = [AllowAny]  # Разрешаем доступ без токена
    def delete(self, request, *args, **kwargs):
        # Получение данных из тела запроса
        user_id = request.data.get('id', None)  # Берем id из URL, если он есть
        user_email = request.data.get('email', None)

        try:
            if user_id:         # удаление по id
                user = User.objects.get(id=user_id)
            elif user_email:    # удаление по email
                user = User.objects.get(email=user_email)
            else:
                return Response(
                    {"error": "No valid identifier provided. Use id or email."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.delete()
            return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
            

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_data(request):
    user = request.user
    data = {                  # данные пользователя
        "email": user.email,
        "name": user.name,
        "quantity": user.quantity,
    }
    return Response(data)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_name(request):
    user = request.user
    new_name = request.data.get("name", "").strip()

    if not new_name:
        return Response({"error": "Имя не может быть пустым."}, status=400)

    user.name = new_name        # Обновляем имя
    user.save(update_fields=["name"])
    return Response({"message": "Имя успешно обновлено.", "name": user.name})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_quantity(request):
    user = request.user
    quantity_to_add = request.data.get('quantity', 0)

    if not isinstance(quantity_to_add, int):
        return Response({"error": "Invalid quantity value"}, status=400)

    user.quantity += quantity_to_add    # Обновляем количество вопросов
    user.save(update_fields=["quantity"])
    return Response({"message": "Количество вопросов обновлено", "total_quantity": user.quantity})