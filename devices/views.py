# tu_aplicacion/views.py
from django.shortcuts import render
from django.http import HttpResponse
from .utils import Verification  # Define esta función en un archivo utils.py
from .models import Device #importa el modelo Device

def index(request):
    
    devices = Device.objects.all()
    
    if request.method == 'POST':
        # Obtén los datos del formulario
        user = request.POST.get('user')
        password = request.POST.get('password')
        ruta = request.POST.get('ruta')

        # Realiza la verificación de dispositivos (usa la función que defines en utils.py)
        resultados = Verification(user, password, ruta)
        
        # Guarda los resultados en la base de datos
        for resultado in resultados:
            device = Device(
                ip=resultado['ip'],
                hostname=resultado['hostname'],
                syslog=resultado['syslog'],
                web_access=resultado['web_access'],
                ssh=resultado['ssh'],
                snmp=resultado['snmp'],
                users=resultado['users'],
                ntp=resultado['ntp'],
                no_telnet=resultado['no_telnet'],
                inactivity=resultado['inactivity'],
                interfaces=resultado['interfaces'],
                protocols=resultado['protocols'],
                policies=resultado['policies']
            )
            device.save()
            
        # Actualiza la lista de dispositivos después de guardar en la base de datos
        devices = Device.objects.all()

        # # Pasa los resultados a la plantilla
        # return render(request, 'resultado.html', {'resultados': device})

    return render(request, 'index.html', {'devices' : devices})

