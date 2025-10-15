# mermind/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("generate/", views.generate_mermaid, name="mermind_generate"),
    path("save/", views.save_diagram, name="mermind_save"),
    path("list/", views.list_diagrams),
    path("<int:pk>/", views.diagram_detail, name="mermind_detail"),
    path("adjust/", views.adjust_mermaid, name="mermind_adjust"),
]
