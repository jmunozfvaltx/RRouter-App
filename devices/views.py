# tu_aplicacion/views.py
from django.shortcuts import render
from django.http import HttpResponse
from .utils import Verification  # Define esta función en un archivo utils.py

def index(request):
    if request.method == 'POST':
        # Obtén los datos del formulario
        user = request.POST.get('user')
        password = request.POST.get('password')
        ruta = request.POST.get('ruta')

        # Realiza la verificación de dispositivos (usa la función que defines en utils.py)
        resultados = Verification(user, password, ruta)

        # Pasa los resultados a la plantilla
        return render(request, 'resultado.html', {'resultados': resultados})

    return render(request, 'index.html')

