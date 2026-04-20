'''
Created on 17 jul. 2018

@author: pgg

aumentar el limite de los campos del indice. importante por la cantidad de campos que se recogen de las tramas

curl -XPUT 'localhost:9200/my_index/_settings' -H 'Content-Type: application/json' -d'{"index" : {"mapping" : {"total_fields" : {"limit" : "100000"}}}}'

'''
import pyshark
import json
import os
import time

# Colores ANSI
R  = '\033[0m'
B  = '\033[1m'
DM = '\033[2m'
CY = '\033[96m'
GR = '\033[92m'
YL = '\033[93m'
MG = '\033[95m'
RD = '\033[91m'
BL = '\033[94m'

# Color por capa OSI
LAYER_COLOR = {
    'eth': BL, 'arp': BL,
    'ip': GR, 'ipv6': GR, 'icmp': GR,
    'tcp': YL, 'udp': YL,
    'dns': MG, 'http': MG, 'tls': MG,
    'imap': MG, 'ftp': MG, 'ssh': MG, 'smtp': MG,
}

# Descripción educativa de las capas más comunes del modelo OSI/TCP-IP
LAYER_INFO = {
    'eth':  'Capa 2 (Enlace) — Trama Ethernet. Contiene MACs origen/destino.',
    'ip':   'Capa 3 (Red)    — Paquete IP. Contiene IPs origen/destino y TTL.',
    'ipv6': 'Capa 3 (Red)    — Paquete IPv6. Versión moderna del protocolo IP.',
    'tcp':  'Capa 4 (Transporte) — Segmento TCP. Conexión fiable con puertos y flags.',
    'udp':  'Capa 4 (Transporte) — Datagrama UDP. Sin conexión, más rápido que TCP.',
    'icmp': 'Capa 3 (Red)    — Mensaje ICMP. Diagnóstico y control (ping, traceroute).',
    'dns':  'Capa 7 (Aplicación) — Consulta/respuesta DNS. Traduce nombres a IPs.',
    'http': 'Capa 7 (Aplicación) — Petición/respuesta HTTP. Tráfico web sin cifrar.',
    'tls':  'Capa 7 (Aplicación) — TLS/SSL. Cifrado de la capa de transporte.',
    'arp':  'Capa 2 (Enlace) — ARP. Resuelve IPs a MACs en la red local.',
    'imap': 'Capa 7 (Aplicación) — IMAP. Protocolo de correo. Sin TLS, en texto claro.',
    'ftp':  'Capa 7 (Aplicación) — FTP. Transferencia de ficheros, sin cifrado.',
    'ssh':  'Capa 7 (Aplicación) — SSH. Acceso remoto cifrado.',
    'smtp': 'Capa 7 (Aplicación) — SMTP. Envío de correo electrónico.',
}

# Interpretación de tipos ICMP más comunes
ICMP_TYPES = {
    '0':  'Echo Reply (respuesta a ping)',
    '3':  'Destination Unreachable (destino inalcanzable)',
    '5':  'Redirect (redirección de ruta)',
    '8':  'Echo Request (ping)',
    '11': 'Time Exceeded (TTL agotado — usado por traceroute)',
    '12': 'Parameter Problem (error en cabecera IP)',
}


class NetSniffer(object):
    '''
    Clase para obtener los paquetes de una red
    '''
    debug_mode = False
        
    # project name
    project_name = 'test'
    base_folder = '../captured_data/'
    
    # net
    interfaces = None
    filters = None
    solo_resumen = True
    
    # parser
    patron = None
    
    # monitor system
    monitor_system = None
    
    def __init__(self, debug_mode, monitor_system, project_name, pattern_parser, interface, custome_filters='', solo_resumen=True):
        '''
        Constructor
        '''
        self.debug_mode = debug_mode
        self.monitor_system = monitor_system
        os.makedirs(self.base_folder, exist_ok=True)
        self.project_name = f'{self.base_folder}/{project_name}.json'
        
        # net
        self.interfaces = interface
        self.solo_resumen = solo_resumen
        
        # parser
        self.patron = pattern_parser
        
        # filtros
        self.filters = custome_filters

    def __print_fields_data(self, p, list_names, space, f=None):
        for n in list_names:
            a = str(space) + '-> ' + str(n) + ': ' + str(getattr(p, n))
            if f:
                f.write(a + '\n')
            print(a)
            
    def __add_fields_data(self, p, list_names, data_dict):
        for n in list_names:
            if n:
                field_data = getattr(p, n)
                if field_data:
                    data_dict[n] = field_data
        return data_dict

    def __describe_packet(self, packet):
        """Imprime un resumen educativo de las capas del paquete."""
        layer_names = [l.layer_name for l in packet.layers]
        pila = ' → '.join(f'{LAYER_COLOR.get(n, R)}{n.upper()}{R}' for n in layer_names)
        print(f'\n  {B}Paquete capturado{R} | Pila: {pila}')

        for layer in packet.layers:
            name = layer.layer_name
            color = LAYER_COLOR.get(name, R)
            desc = LAYER_INFO.get(name, f'Capa desconocida: {name}')
            print(f'    {color}{B}[{name.upper():8}]{R} {desc}')

            # anotaciones específicas por protocolo
            if name == 'icmp' and hasattr(layer, 'type'):
                tipo = str(layer.type)
                significado = ICMP_TYPES.get(tipo, 'Tipo no común')
                print(f'             {GR}→ Tipo ICMP {B}{tipo}{R}{GR}: {significado}{R}')

            if name == 'ip' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                ttl = getattr(layer, 'ttl', '?')
                print(f'             {GR}→ {B}{layer.src}{R}{GR} → {B}{layer.dst}{R}{GR}  (TTL: {ttl}){R}')

            if name == 'eth' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                print(f'             {BL}→ MAC src: {B}{layer.src}{R}{BL}  |  MAC dst: {B}{layer.dst}{R}')

            if name == 'tcp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                flags = getattr(layer, 'flags_str', '')
                print(f'             {YL}→ Puerto {B}{layer.srcport}{R}{YL} → {B}{layer.dstport}{R}{YL}  flags: {flags}{R}')

            if name == 'udp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                print(f'             {YL}→ Puerto {B}{layer.srcport}{R}{YL} → {B}{layer.dstport}{R}')

            if name == 'dns' and hasattr(layer, 'qry_name'):
                print(f'             {MG}→ Consulta DNS: {B}{layer.qry_name}{R}')

            if name == 'imap' and hasattr(layer, 'request_command'):
                print(f'             {RD}{B}⚠️  Comando IMAP visible: {layer.request_command}{R}')

            print(f'          {DM}Datos de la capa:{R}')
            layer.pretty_print()

        print(f'  {DM}{"─" * 56}{R}')

    def __capture_resume(self, capture):
        print(f'\n  {CY}Escuchando la red.{R} Cada bloque es un paquete capturado.')
        print(f'  Pulsa {YL}Ctrl+C{R} para detener la captura.')
        time.sleep(10)
        print(f'  {DM}{"─" * 56}{R}')

        layers_to_check = []

        for packet in capture.sniff_continuously():
            if len(layers_to_check) > 0:
                for l in packet.layers:
                    if l.layer_name in layers_to_check:
                        self.__describe_packet(packet)
                        break
            else:
                self.__describe_packet(packet)
    
    def __capture_all(self, capture):
        for packet in capture.sniff_continuously():
            data_dict = {'layers':{}}
            frame_info = packet.frame_info
            for frame_field in frame_info.field_names:
                data_dict[frame_field] = getattr(frame_info, frame_field)            
                
            available_layers = packet.layers
            for l in available_layers:
                
                layer_data = {'layer_name':l.layer_name}
                data_dict['layers'][l.layer_name] = layer_data
                self.__add_fields_data(l, l.field_names, layer_data)
                
                ml = packet.get_multiple_layers(l.layer_name)
                for ml_tmp in ml:
                    if ml_tmp.layer_name != l.layer_name:
                        sub_layer_data = {'sub_layer_name':ml_tmp.layer_name}
                        layer_data['layer_' + str(l.layer_name)] = sub_layer_data
                        self.__add_fields_data(l, l.field_names, layer_data)
                        self.__add_fields_data(ml_tmp, ml_tmp.field_names, sub_layer_data)

            # generamos el dict del patron
            data_dict = self.patron.process_log_data(data_dict)

            if data_dict:
                self.__write_new_packet_data(data_dict)

    def __write_new_packet_data(self, packet_data):
        with open(self.project_name, 'a') as archivo:
            json.dump(packet_data, archivo)
            archivo.write('\n')

        campos = {k: v for k, v in packet_data.items() if v and k not in ('db_name', 'layer_name')}
        resumen = '  |  '.join(f'{CY}{k}{R}: {YL}{v}{R}' for k, v in list(campos.items())[:4])
        print(f'  {GR}{B}[GUARDADO]{R} {resumen}')

        if self.monitor_system:
            packet_data['indice'] = 'redes1'
            clase_name = self.project_name.replace(f'{self.base_folder}/', '').replace('.json', '')
            self.monitor_system.send_data(clase_name, packet_data)
            print(f'  {MG}[LOGSTASH]{R} Paquete enviado al sistema de monitorización')

    def __init_capture(self):
        
        capture = pyshark.LiveCapture(
            interface=self.interfaces,
            bpf_filter=self.filters
            )
        
        if self.solo_resumen:
            self.__capture_resume(capture)
        else:
            self.__capture_all(capture)
    
    def comenzar(self):
        sep = f'{CY}{"─" * 60}{R}'
        print(f'\n{sep}')
        print(f'  {B}{CY}¿QUÉ ES UN SNIFFER?{R}')
        print(f'  Un sniffer (o analizador de paquetes) captura el tráfico')
        print(f'  que circula por una interfaz de red. Permite inspeccionar')
        print(f'  los protocolos y datos de cada comunicación en tiempo real.')
        print(f'{sep}')
        print(f'  {CY}Interfaz escuchada{R} : {YL}{B}{", ".join(self.interfaces)}{R}')
        print(f'  {DM}(la interfaz es el adaptador de red físico o virtual que recibe los paquetes){R}')
        filtro = self.filters if self.filters else f'{DM}ninguno — se captura todo el tráfico{R}'
        print(f'  {CY}Filtro BPF activo{R}  : {YL}{filtro}{R}')
        print(f'  {DM}(BPF = Berkeley Packet Filter, permite acotar qué paquetes capturar){R}')
        print(f'  {CY}Datos guardados en{R} : {GR}{self.project_name}{R}')
        print(f'{sep}\n')
        self.__init_capture()
