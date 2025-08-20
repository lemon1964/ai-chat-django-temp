# ai-chat-django/chat_app/views.py
from rest_framework import status, mixins, viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.db.models import F
from rest_framework.decorators import api_view, permission_classes
from .models import Category, Question, Answer
from .serializers import CategorySerializer, QuestionSerializer, AnswerSerializer
from .model_providers.openrouter.selector import get_top_models
from .model_providers.openrouter.query import query_openrouter


class CategoryViewSet(
    mixins.ListModelMixin,
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    permission_classes = [IsAuthenticated]
    serializer_class = CategorySerializer

    def get_queryset(self):
        return Category.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class QuestionViewSet(
    mixins.ListModelMixin, mixins.CreateModelMixin, viewsets.GenericViewSet
):
    permission_classes = [IsAuthenticated]
    serializer_class = QuestionSerializer

    def get_queryset(self):
        category_pk = self.kwargs.get("category_pk")
        return Question.objects.filter(category_id=category_pk, user=self.request.user)

    def perform_create(self, serializer):
        serializer.save()
        self.request.user.quantity = F("quantity") + 1
        self.request.user.save(update_fields=["quantity"])

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        question = Question.objects.get(id=response.data["id"])
        serializer = self.get_serializer(question)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class AnswerViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = AnswerSerializer

    def get_queryset(self):
        question_pk = self.kwargs.get("question_pk")
        return Answer.objects.filter(question_id=question_pk)


@api_view(["GET"])
@permission_classes([AllowAny])
def get_models(request):
    print("Запрос на получение моделей в OpenRouter")
    return Response(get_top_models())


@api_view(["POST"])
@permission_classes([AllowAny])
def ask_model(request):
    data = request.data

    result = query_openrouter(
        prompt=data["prompt"],
        model_id=data["model_id"],
        language=data.get("language", "en"),
    )
    return Response(result)
