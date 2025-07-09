# ai-chat-django/chat_app/admin.py
from django.contrib import admin
from django.utils.safestring import mark_safe
from .models import Category, Question, Answer, GeneratedImage

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    """Админка категорий"""
    list_display = ("name", "id", "owner")
    search_fields = ("name", "owner__email")
    list_select_related = ("owner",)

@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    """Админка вопросов"""
    list_display = ("truncated_prompt", "category", "id", "user", "model_type")
    search_fields = ("prompt", "category__name", "user__email")
    list_filter = ("model_type", "created_at")
    
    def truncated_prompt(self, obj):
        return obj.prompt[:50] + "..." if len(obj.prompt) > 50 else obj.prompt
    truncated_prompt.short_description = "Prompt"

@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    """Админка ответов"""
    list_display = ("truncated_content", "question", "id", "tokens_used")
    search_fields = ("content", "question__prompt")
    
    def truncated_content(self, obj):
        return obj.content[:50] + "..." if len(obj.content) > 50 else obj.content
    truncated_content.short_description = "Content"

@admin.register(GeneratedImage)
class GeneratedImageAdmin(admin.ModelAdmin):
    """Админка сгенерированных изображений"""
    list_display = ("prompt", "preview", "id", "created_at")
    readonly_fields = ("preview",)
    
    def preview(self, obj):
        if obj.file:  # Проверяем наличие файла
            return mark_safe(f'<img src="{obj.file.url}" style="max-height: 100px;" />')
        elif obj.url:  # Если нет файла, но есть URL
            return mark_safe(f'<img src="{obj.url}" style="max-height: 100px;" />')
        return "No image available"
    preview.short_description = "Preview"