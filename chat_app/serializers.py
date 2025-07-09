# ai-chat-django/chat_app/serializers.py
from rest_framework.response import Response
from rest_framework import serializers
from .models import Category, Question, Answer, GeneratedImage
from django.conf import settings
from .utils import query_provider
from .ai_providers.image_models import query_flux_image


class AnswerSerializer(serializers.ModelSerializer):
    """Сериализатор для ответов ИИ с поддержкой изображений."""
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = Answer
        fields = ['id', 'question', 'content', 'image_url', 'tokens_used', 'created_at']

    def get_image_url(self, obj):
        # Если content — это путь к файлу изображения
        if obj.content and obj.content.startswith(settings.MEDIA_URL):
            return obj.content
        return None


class QuestionSerializer(serializers.ModelSerializer):
    """Сериализатор для вопросов с автоматической генерацией ответов."""
    model_type = serializers.CharField(write_only=True)
    model = serializers.CharField(write_only=True)
    answers = AnswerSerializer(many=True, read_only=True)
    category_id = serializers.UUIDField(write_only=True)
    language = serializers.CharField(write_only=True)

    class Meta:
        model = Question
        fields = ['id', 'category', 'category_id', 'user', 'prompt', 'model', 'model_type', 'created_at', 'answers', 'language']
        read_only_fields = ['category', 'user', 'created_at', 'answers']

    def create(self, validated_data):
        """Автоматически создаёт ответ через AI-провайдер при сохранении вопроса."""
        model_type = validated_data.pop('model_type')
        model_name = validated_data.pop('model')
        prompt_text = validated_data.get('prompt')
        category_id = validated_data.pop('category_id')
        language = validated_data.pop('language', 'en')
        
        # Получаем объект категории
        category = Category.objects.get(id=category_id)
        user = self.context['request'].user
        
        question = Question.objects.create(
            prompt=prompt_text,
            category=category,
            user=user,
            model=model_name,
            model_type=model_type
        )
        
        # Обработка изображений
        if model_type == 'image':
            image_url, error = query_flux_image(prompt_text)
            if error:
                return Response({"error": error}, status=400)
                
            Answer.objects.create(
                question=question,
                content=image_url,  # Сохраняем URL изображения
                tokens_used=0  # Для изображений не считаем токены
            )
        # Обработка текста/кода
        else:
            text, tokens = query_provider(prompt_text, model_type, model_name, language)
            Answer.objects.create(
                question=question,
                content=text,
                tokens_used=tokens
            )    
 
        return question


class CategorySerializer(serializers.ModelSerializer):
    """Сериализатор для категорий с вложенными вопросами."""
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Category
        fields = ['id', 'name', 'owner', 'questions']
        read_only_fields = ['owner']


class GeneratedImageSerializer(serializers.ModelSerializer):
    """Сериализатор для сгенерированных изображений."""
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = GeneratedImage
        fields = ['id', 'file_url', 'prompt', 'created_at']

    def get_file_url(self, obj):
        """Возвращает URL файла изображения, если он существует."""
        return obj.file.url if obj.file else None