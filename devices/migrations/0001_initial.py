# Generated by Django 5.0 on 2023-12-12 22:01

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.GenericIPAddressField()),
                ('hostname', models.CharField(max_length=255)),
                ('syslog', models.CharField(max_length=255)),
                ('web_access', models.CharField(max_length=255)),
                ('ssh', models.CharField(max_length=255)),
                ('snmp', models.CharField(max_length=255)),
                ('users', models.CharField(max_length=255)),
                ('ntp', models.CharField(max_length=255)),
                ('no_telnet', models.CharField(max_length=255)),
                ('inactivity', models.CharField(max_length=255)),
                ('interfaces', models.CharField(max_length=255)),
                ('protocols', models.CharField(max_length=255)),
                ('policies', models.CharField(max_length=255)),
            ],
        ),
    ]
