# tu_aplicacion/urls.py
from django.urls import path
#from .views import index
from .views import dashboard,logout_view, sw_interface, profile, CustomLoginView

urlpatterns = [
    #path('', index, name='index'),
    path('', CustomLoginView.as_view(), name='custom_login'),  # Ruta principal para login
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard, name='dashboard'),
    path('sw_interface', sw_interface, name='sw_interface'),
    path('profile', profile, name="profile"),
    path('login_builtin/', CustomLoginView.as_view(), name='login_builtin'),
]
