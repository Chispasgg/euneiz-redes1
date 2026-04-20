'''
Created on 14 jun. 2018

@author: pgg
'''
from utils.ConfigReader import ConfigReader
import os

# Colores ANSI
R  = '\033[0m'       # reset
B  = '\033[1m'       # bold
DM = '\033[2m'       # dim
CY = '\033[96m'      # cyan
GR = '\033[92m'      # verde
YL = '\033[93m'      # amarillo
MG = '\033[95m'      # magenta
RD = '\033[91m'      # rojo

from enviodatos.EnvioDatosLogstash import EnvioDatosLogstash
from net.NetSniffer import NetSniffer
# patrones
from lectura_logs.patrones.connPatron import connPatron
from lectura_logs.patrones.pcapLivePatron import pcapLivePatron
from lectura_logs.patrones.curso_2025.icmpPatron import icmpPatron
from lectura_logs.patrones.curso_2025.imapPatron import imapPatron

# procesamiento de logs
logs_patterns_types = {
    'conn': connPatron,
    'pcap_live':pcapLivePatron,
    # 2025
    'icmp':icmpPatron,
    'imap':imapPatron
    # meter los patrones de lectura de logs aqui
}

# Información educativa por patrón: protocolo, capa OSI, descripción, campos relevantes
PATRON_INFO = {
    'conn': {
        'protocolo': 'Ethernet',
        'capa': 'Capa 2 — Enlace de datos',
        'descripcion': 'Analiza tramas Ethernet. Permite ver las direcciones MAC de los dispositivos que se comunican directamente en la red local. El OUI (Organizationally Unique Identifier) identifica al fabricante del adaptador de red.',
        'campos': 'MAC origen, MAC destino, OUI fabricante, tipo de trama',
        'ejemplo': 'Útil para descubrir qué dispositivos hay en la red y a qué fabricante pertenece cada tarjeta de red.',
    },
    'pcap_live': {
        'protocolo': 'Genérico (todas las capas)',
        'capa': 'Capas 2–7',
        'descripcion': 'Captura todos los paquetes sin filtrado de protocolo. Muestra la pila de capas completa de cada paquete tal como llega.',
        'campos': 'Todas las capas disponibles en cada paquete',
        'ejemplo': 'Útil para exploración inicial: ver qué protocolos circulan por la red.',
    },
    'icmp': {
        'protocolo': 'ICMP (Internet Control Message Protocol)',
        'capa': 'Capa 3 — Red',
        'descripcion': 'ICMP es el protocolo de mensajes de control de Internet. No transporta datos de usuario, sino señales de diagnóstico y error. El comando "ping" usa ICMP tipo 8 (Echo Request) y tipo 0 (Echo Reply). Traceroute usa ICMP tipo 11 (Time Exceeded).',
        'campos': 'type, code, checksum, ident, seq, data',
        'ejemplo': 'Ejecuta "ping 8.8.8.8" en otro terminal y verás los paquetes aparecer aquí.',
    },
    'imap': {
        'protocolo': 'IMAP (Internet Message Access Protocol)',
        'capa': 'Capa 7 — Aplicación',
        'descripcion': 'IMAP es el protocolo para leer correo electrónico desde un servidor. Sin TLS/SSL, las credenciales (usuario y contraseña) viajan en texto claro por la red y son completamente visibles para cualquier sniffer. Este patrón demuestra ese riesgo.',
        'campos': 'comando, usuario, contraseña, tag, línea completa',
        'ejemplo': '⚠️  Las credenciales capturadas aquí son visibles porque IMAP sin cifrado no protege los datos en tránsito.',
    },
}

    
def __launch_net_process(debug_mode, monitor_system, project_name, log_type, interfaces, custome_filters='', solo_resumen=True):
    lg = NetSniffer(debug_mode, monitor_system, project_name, log_type, interfaces, custome_filters, solo_resumen)
    lg.comenzar()


def __get_current_log_patterns(log_type, log_path):
    try:
        return logs_patterns_types[log_type](log_path)
    except KeyError:
        print(f'\n{RD}{B}[ERROR]{R} El patrón "{RD}{log_type}{R}" no existe.')
        print(f'        Patrones disponibles: {YL}{", ".join(logs_patterns_types.keys())}{R}')
        print(f'        Revisa el valor de {CY}log_type{R} en conf/conf.ini')
        exit(0)


def __print_patron_info(log_type):
    info = PATRON_INFO.get(log_type)
    if not info:
        return
    sep = f'{CY}{"─" * 60}{R}'
    print(f'\n{sep}')
    print(f'  {B}{CY}PATRÓN ACTIVO{R}  : {B}{YL}{log_type.upper()}{R}')
    print(f'  {CY}Protocolo{R}      : {GR}{info["protocolo"]}{R}')
    print(f'  {CY}Capa OSI{R}       : {MG}{info["capa"]}{R}')
    print(f'  {CY}Campos{R}         : {DM}{info["campos"]}{R}')
    print(f'{sep}')
    print(f'  {info["descripcion"]}')
    print(f'\n  {YL}{info["ejemplo"]}{R}')
    print(f'{sep}\n')


if __name__ == '__main__':
    print(f'{CY}Iniciando...{R}')

    # cargamos la configuracion
    config_file = (os.path.dirname(os.path.realpath(__file__)).replace('/src', '')) + '/conf/conf.ini'
    config = ConfigReader(config_file)

    print("")
    print(f'{B}{CY}' + r"  _           _____   _____  _____  " + f'{R}')
    print(f'{B}{CY}' + r" | |         |  __ \ / ____|/ ____| " + f'{R}')
    print(f'{B}{CY}' + r" | |__  _   _| |__) | |  __| |  __  " + f'{R}')
    print(f'{B}{CY}' + r" | '_ \| | | |  ___/| | |_ | | |_ | " + f'{R}')
    print(f'{B}{CY}' + r" | |_) | |_| | |    | |__| | |__| | " + f'{R}')
    print(f'{B}{CY}' + r" |_.__/ \__, |_|     \_____|\_____| " + f'{R}')
    print(f'{B}{CY}' + r"         __/ |                      " + f'{R}')
    print(f'{B}{CY}' + r"        |___/                       " + f'{R}')
    print(f'{DM}  Sniffer de red — Grado en Seguridad EUNEIZ{R}')
    print("")
    
    debug_mode = config.getBoolean('GlobalConfig', 'debug_mode')
    
    # sistema de monitorizacion externa
    monitor_system_enable = False
    monitor_system_ip = None
    monitor_system_port = None
    envio_de_datos = None
    try:
        monitor_system_enable = config.getBoolean('MonitorSystem', 'monitor_system_enable')
    except:
        pass
    
    if monitor_system_enable:
        monitor_system_ip = config.ConfigSectionMap('MonitorSystem')['monitor_ip']
        monitor_system_port = config.ConfigSectionMap('MonitorSystem')['monitor_port']
        envio_de_datos = EnvioDatosLogstash(monitor_system_ip, monitor_system_port)
        print(f'  {GR}[MONITOR]{R} Logstash activo en {CY}{monitor_system_ip}:{monitor_system_port}{R}')
    
    # sistema de obtencion de datos
    project_name = config.ConfigSectionMap('App')['project_name']
    custome_filters = config.ConfigSectionMap('App')['net_custome_filters']
    
    log_type_name = config.ConfigSectionMap('App')['log_type']
    log_type = __get_current_log_patterns(log_type_name, '')
    __print_patron_info(log_type_name)

    interfaces = config.ConfigSectionMap('App')['net_sniffer_interface']
    interfaces = interfaces.split(',')
    net_summarize = True
    if 'net_summarize' in config.ConfigSectionMap('App'):
        net_summarize = config.getBoolean('App', 'net_summarize')
    __launch_net_process(debug_mode, envio_de_datos, project_name, log_type, interfaces, custome_filters, net_summarize)

    print(f'\n{CY}── Captura finalizada ──{R}')
    print(f'{DM}FIN{R}')
