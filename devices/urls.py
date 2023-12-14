# tu_aplicacion/urls.py
from django.urls import path
#from .views import index
from .views import custom_login, dashboard, sw_interface, CustomLoginView

urlpatterns = [
    #path('', index, name='index'),
    path('', custom_login, name='custom_login'),  # Esta línea añadida
    path('login/', custom_login, name='custom_login'),
    path('dashboard/', dashboard, name='dashboard'),
    path('sw_interface', sw_interface, name='sw_interface'),
    path('login_builtin/', CustomLoginView.as_view(), name='login_builtin'),
]
