# tu_aplicacion/models.py
from django.db import models

class Device(models.Model):
    ip = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255)
    syslog = models.CharField(max_length=255)
    web_access = models.CharField(max_length=255)
    ssh = models.CharField(max_length=255)
    snmp = models.CharField(max_length=255)
    users = models.CharField(max_length=255)
    ntp = models.CharField(max_length=255)
    no_telnet = models.CharField(max_length=255)
    inactivity = models.CharField(max_length=255)
    interfaces = models.CharField(max_length=255)
    protocols = models.CharField(max_length=255)
    policies = models.CharField(max_length=255)

    def __str__(self):
        return self.hostname
