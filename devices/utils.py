# tu_aplicacion/utils.py
from netmiko import ConnectHandler
import os
import time

syslog = ['logging host 118.185.8.206 vrf 10']
accesoWEB = ['no ip http server', 'no ip http secure-server']
configSSH = ['ip ssh version 2', 'ip ssh authentication-retries 3', 'ip ssh server algorithm encryption aes128-ctr aes192-ctr aes256-ctr',
            'ip ssh server algorithm mac hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com hmac-sha2-256 hmac-sha2-512 hmac-sha1',
            '10 permit tcp host 118.180.55.223 any eq 22',
            '70 deny   tcp any any eq 22']
configSSHextended = ['ip access-list extended DENY_SSH_QUALIS_TUX']

SNMPv3 = ['snmp-server group GROUPCONTISNMPV3 v3 priv read BBVAV3',
            'snmp-server host 118.180.55.253 vrf 10 version 3 priv NETCONTIV3 udp-port 161',
            'snmp-server host 118.185.8.40 vrf 10 version 3 priv NETCONTIV3 udp-port 161',
            'snmp-server host 118.185.8.172 vrf 10 version 3 priv NETCONTIV3 udp-port 161',
            'snmp-server host 118.185.8.206 vrf 10 version 3 priv NETCONTIV3 udp-port 161',
            'snmp-server host 118.253.254.245 vrf 10 version 3 priv NETCONTIV3 udp-port 161']

userCONSOLA = ['username admin secret 9',
                'username italtel privilege 15 secret 9',
                'username netoconti privilege 15 secret 9']

userPersonalizado = ['aaa group server tacacs+ tacacs-10',
                        'server-private 118.180.47.40 port 49 timeout 5 key 6',
                        'server-private 118.185.8.217 port 49 timeout 5 key 6',
                        'server-private 118.185.8.218 port 49 timeout 5 key 6',
                        'aaa authentication attempts login 3',
                        'aaa authentication login default group tacacs-10 local',
                        'aaa authorization exec default group tacacs-10 local',
                        'aaa accounting exec default start-stop group tacacs+',
                        'aaa accounting system default start-stop group tacacs+',
                        'aaa accounting commands 15 default start-stop group tacacs+']

serviceNTP = ['ntp server vrf 10 118.180.55.27', 'ntp server vrf 10 118.180.54.12']

noTELNETssh = ['transport input ssh']

inactividad = ['exec-timeout 5 0']

interGgb = ['switchport trunk native vlan 902', 'switchport mode trunk',
            'interface GigabitEthernet0/1/', 'shutdown']

protocoloFTPoSFTP = ['no ip ftp passive', 'no ip tftp claim-netascii']

policy = ['policy-map type inspect DIA_VPN10-40_TO_VPN0_',
        'policy-map type inspect VPN10-20-30-40-TO-VPN312_',
        'policy-map type inspect VPN10-TO-VPN10_',
        'policy-map type inspect VPN312-TO-VPN10-20-30-40_']

policy2 = ['policy-map type inspect ZBFW_SELFZONE_TO_VPN0_',
        'policy-map type inspect ZBFW_VPN0-TO_SELFZONE_']


class Verification:
    def __init__(self, comandos):
        self.comandos = comandos
        self.revision = self.verify()

    def save_hostname(self):
        j = 0
        a = 0
        hos = 'hostname'
        for i in self.comandos:
            caracteres = len(self.comandos[j])
            palabra = str(self.comandos[j])
            nun = str(palabra[:8])

            if hos == nun:
                name = str(palabra[9:])
            else:
                j = j + 1

        return name

    def search_syslog(self):
        #AQUI EMPIEZA LA VERIFICACION
        j = 0
        a = 0
        for i in syslog:
            try:
                ind = self.comandos.index(syslog[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1

        if a == 1:
            return [0]
        elif a != 1:
            return [1]

    def search_webaccess(self):
        #SE VERIFICA ACCESO WEB
        j = 0
        a = 0
        for i in accesoWEB:
            try:
                ind = self.comandos.index(accesoWEB[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1

        if a == 2:
            return [0]
        elif a != 2:
            return [1]

    def search_ssh_configuration(self):
        #SE VERIFICA CONFIGURACION SSH
        j = 0
        a = 0
        for i in configSSH:
            try:
                ind = self.comandos.index(configSSH[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1
        try:
            ind = self.comandos.index("line vty 0 4")
            if ind > 0:
                word1 = self.comandos[ind + 1]
                if str(word1[:32]) == "access-class DENY_SSH_QUALIS_TUX":
                    a = a + 1

            ind = self.comandos.index("line vty 5 80")
            if ind > 0:
                word2 = self.comandos[ind + 1]
                if str(word2[:32]) == "access-class DENY_SSH_QUALIS_TUX":
                    a = a + 1
        except ValueError:
            a = a + 0

        i = 0
        while i < len(self.comandos):
            us = str(configSSHextended[0])
            try:
                palabra = str(self.comandos[i])
                long = us.__len__()
                nun = str(palabra[:long])
                if us == nun:
                    a = a + 1
                    break
            except IndexError:
                a = a + 0
            i += 1

        if a == 9:
            return [0]
        elif a != 9:
            return [1]

    def search_snmpv3_cofiguration(self):
        #SE VERIFICA SNMPv3
        j = 0
        a = 0

        for i in SNMPv3:
            try:
                ind = self.comandos.index(SNMPv3[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1

        if a == 6:
            return [0]
        elif a != 6:
            return [1]

    def search_user_consola(self):
        #SE VERIFICA USUARIOS DE CONSOLA
        j = 0
        a = 0
        i = 0

        for i in userCONSOLA:
            i = 0
            us = str(userCONSOLA[j])
            while i <= len(self.comandos) - 2:
                palabra = str(self.comandos[i])
                long = us.__len__()
                nun = str(palabra[:long])
                if us == nun:
                    a = a + 1
                    break
                else:
                    a = a + 0
                i += 1
            j = j + 1

        if a == 3:
            return [0]
        elif a != 3:
            return [1]

    def search_user_personalized(self):
        #SE VERIFICA USUARIOS PERSONALIZADOS
        j = 0
        a = 0
        for i in userPersonalizado:
            i = 0
            us = str(userPersonalizado[j])
            while i <= len(self.comandos) - 2:
                try:
                    palabra = str(self.comandos[i])
                    long = us.__len__()
                    nun = str(palabra[:long])
                    if us == nun:
                        a = a + 1
                        break
                except IndexError:
                    a = a + 0
                i += 1
            j = j + 1

        if a == 10:
            return [0]
        elif a != 10:
            return [1]

    def search_ntp_service(self):
        #SE VERIFICA SERVICIO NTP
        j = 0
        a = 0
        for i in serviceNTP:
            try:
                ind = self.comandos.index(serviceNTP[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1
                a = a + 0

        if a == 2:
            return [0]
        elif a != 2:
            return [1]

    def search_telnet_ssh_disable(self):
        #SE VERIFICA DESHABILITACION TELNET Y ACT SSH
        j = 0
        a = 0
        telnetsito = ["line vty 0 4", "line vty 5 80"]
        try:
            ind = self.comandos.index(telnetsito[0])
            if str(self.comandos[ind + 2]) == str(noTELNETssh[0]):
                a = a + 1
            elif str(self.comandos[ind + 3]) == str(noTELNETssh[0]):
                a = a + 1
            elif str(self.comandos[ind + 4]) == str(noTELNETssh[0]):
                a = a + 1
            elif str(self.comandos[ind + 5]) == str(noTELNETssh[0]):
                a = a + 1
            else:
                a += 0

            ind = self.comandos.index(telnetsito[1])
            if str(self.comandos[ind + 2]) == str(noTELNETssh[0]):
                a = a + 1
            elif str(self.comandos[ind + 3]) == str(noTELNETssh[0]):
                a = a + 1
            else:
                a += 0
        except ValueError:
            a += 0

        if a == 2:
            return [0]
        elif a != 2:
            return [1]

    def search_inactivity(self):
        #SE VERIFICA CONF POR TIEMPO DE DESCONEXIÓN
        j = 0
        a = 0
        for i in inactividad:
            try:
                ind = self.comandos.index(inactividad[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1
                a = a + 0

        if a == 1:
            return [0]
        elif a != 1:
            return [1]

    def search_shutdown_ports(self):
        #SE VERIFICA SHUTDOWN GgEth
        j = 0
        a = 0
        try:
            ind = self.comandos.index(interGgb[0])
            if str(interGgb[1]) == str(self.comandos[ind + 2]):
                a = a + 1

            x = 1
            while x < 8:
                ind = self.comandos.index(interGgb[2] + str(x))
                if str(interGgb[3]) == str(self.comandos[ind + 2]):
                    a = a + 1
                x = x + 1

        except ValueError:
            x = x + 1

        if a == 8:
            return [0]
        elif a != 8:
            return [1]

    def search_ftp_or_sftp_protocol(self):
        #SE VERIFICA DESH DE PROTOCOLO FTP/SFTP
        j = 0
        a = 0
        for i in protocoloFTPoSFTP:
            try:
                ind = self.comandos.index(protocoloFTPoSFTP[j])
                if ind > 0:
                    j = j + 1
                    a = a + 1
            except ValueError:
                j = j + 1

        if a == 2:
            return [0]
        elif a != 2:
            return [1]

    def search_policies(self):
        #SE VERIFICA DE POLITICAS
        j = 0
        a = 0
        for i in policy:
            i = 0
            us = str(policy[j])
            while i <= len(self.comandos) - 2:
                try:
                    palabra = str(self.comandos[i])
                    long = us.__len__()
                    nun = str(palabra[:long])
                    if us == nun:
                        a = a + 1
                        break
                except IndexError:
                    a = a + 0
                i += 1
            j = j + 1

        j = 0
        for i in policy2:
            i = 0
            us = str(policy2[j])
            while i <= len(self.comandos) - 2:
                try:
                    palabra = str(self.comandos[i])
                    long = us.__len__()
                    nun = str(palabra[:long])
                    if us == nun:
                        a = a + 1
                        break
                except IndexError:
                    a = a + 0
                i += 1
            j = j + 1

        if a == 6:
            return [0]
        elif a != 6:
            return [1]

    def verify(self):
        revision = []
        revision.append(self.save_hostname())
        revision.extend(self.search_syslog())
        revision.extend(self.search_webaccess())
        revision.extend(self.search_ssh_configuration())
        revision.extend(self.search_snmpv3_cofiguration())
        revision.extend(self.search_user_consola())
        revision.extend(self.search_user_personalized())
        revision.extend(self.search_ntp_service())
        revision.extend(self.search_telnet_ssh_disable())
        revision.extend(self.search_inactivity())
        revision.extend(self.search_shutdown_ports())
        revision.extend(self.search_ftp_or_sftp_protocol())
        revision.extend(self.search_policies())

        return revision

