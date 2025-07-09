# ai-chat-django/chat_app/models.py
from django.db import models
import uuid
from django.contrib.auth import get_user_model

User = get_user_model()

class Category(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    owner = models.ForeignKey(User, related_name='categories', on_delete=models.CASCADE)
    
    def __str__(self):
        return self.name

class Question(models.Model):
    TEXT = 'text'
    CODE = 'code'
    IMAGE = 'image'
    MODEL_TYPES = [
        (TEXT, 'Text'),
        (CODE, 'Code'),
        (IMAGE, 'Image'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name="questions")
    user = models.ForeignKey(User, related_name='question_user', on_delete=models.CASCADE)
    prompt = models.TextField()
    model_type = models.CharField(max_length=10, choices=MODEL_TYPES, blank=True, null=True)
    model = models.CharField(max_length=70, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.prompt[:20]} by {self.user}"
    
    class Meta:
        ordering = ["-created_at"]  # самую «свежую» сверху

class Answer(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name="answers")
    content = models.TextField()
    tokens_used = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        # выводим первые 20 символов ответа
        return f"{self.question} → {self.content[:20]}…"

    class Meta:
        ordering = ["-created_at"]
        
        
class GeneratedImage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    file = models.ImageField(upload_to='generated/')
    prompt = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    source_url = models.URLField(null=True, blank=True)
    url = models.URLField(max_length=500, null=True, blank=True)

    def __str__(self):
        return f"Image for: {self.prompt[:50]}..."
    
    class Meta:
        ordering = ["-created_at"]
