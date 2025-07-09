# ai-chat-django/chat_app/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoryViewSet, QuestionViewSet, AnswerViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet, basename='category')
router.register(
    r'categories/(?P<category_pk>[^/.]+)/questions',
    QuestionViewSet,
    basename='question'
)
router.register(
    r'questions/(?P<question_pk>[^/.]+)/answers',
    AnswerViewSet,
    basename='answer'
)

urlpatterns = [
    path('', include(router.urls)),
]