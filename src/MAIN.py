'''
Created on 14 jun. 2018

@author: pgg
'''
from utils.ConfigReader import ConfigReader
import os
from net.NetSniffer import NetSniffer

# patrones
from lectura_logs.patrones.connPatron import connPatron
from lectura_logs.patrones.httpPatron import httpPatron
from lectura_logs.patrones.sslPatron import sslPatron
from lectura_logs.patrones.sshPatron import sshPatron
from lectura_logs.patrones.dnsPatron import dnsPatron
from lectura_logs.patrones.pcapLivePatron import pcapLivePatron
from enviodatos.EnvioDatosLogstash import EnvioDatosLogstash

# procesamiento de logs
logs_patterns_types = {
    'conn': connPatron,
    'http': httpPatron,
    'ssl':sslPatron,
    'ssh':sshPatron,
    'dns':dnsPatron,
    'pcap_live':pcapLivePatron
}

    
def __launch_net_process(debug_mode, monitor_system, project_name, log_type, interfaces, custome_filters='', solo_resumen=True): 
    lg = NetSniffer(debug_mode, monitor_system, project_name, log_type, interfaces, custome_filters, solo_resumen)
    lg.comenzar()


def __get_current_log_patterns(log_type, log_path): 
    try:
        return logs_patterns_types[log_type](log_path)
    except KeyError:
        print('No existe ese patron {}'.format(log_type))
        exit(0)


if __name__ == '__main__':
    print('INICIO')
    
    # cargamos la configuracion
    config_file = (os.path.dirname(os.path.realpath(__file__)).replace('/src', '')) + '/conf/conf.ini'
    config = ConfigReader(config_file)
#     print(config.sections())

    print("")
    print("  _           _____   _____  _____  ")
    print(" | |         |  __ \ / ____|/ ____| ")
    print(" | |__  _   _| |__) | |  __| |  __  ")
    print(" | '_ \| | | |  ___/| | |_ | | |_ | ")
    print(" | |_) | |_| | |    | |__| | |__| | ")
    print(" |_.__/ \__, |_|     \_____|\_____| ")
    print("         __/ |                      ")
    print("        |___/                       ")
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
    
    # sistema de obtencion de datos
    project_name = config.ConfigSectionMap('App')['project_name']
    custome_filters = config.ConfigSectionMap('App')['net_custome_filters']
    
    print('  --> Patron de Red live')
    log_type = __get_current_log_patterns(config.ConfigSectionMap('App')['log_type'], '')
    # log_type = __get_current_log_patterns("pcap_live", '')
    interfaces = config.ConfigSectionMap('App')['net_sniffer_interface']
    interfaces = interfaces.split(',')
    net_summarize = True
    if 'net_summarize' in config.ConfigSectionMap('App'):
        net_summarize = config.getBoolean('App', 'net_summarize')
    __launch_net_process(debug_mode, envio_de_datos, project_name, log_type, interfaces, custome_filters, net_summarize)
        
    print('----------------')
    
    print('FIN')
