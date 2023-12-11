# tu_aplicacion/urls.py
from django.urls import path
from .views import index

urlpatterns = [
    path('', index, name='index'),
]
