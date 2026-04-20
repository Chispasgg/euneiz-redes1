'''
Created on 17 jul. 2018

@author: pgg

aumentar el limite de los campos del indice. importante por la cantidad de campos que se recogen de las tramas

curl -XPUT 'localhost:9200/my_index/_settings' -H 'Content-Type: application/json' -d'{"index" : {"mapping" : {"total_fields" : {"limit" : "100000"}}}}'

'''
import pyshark
import json
import os

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
        pila = ' → '.join(layer_names).upper()
        print(f'\n  Paquete capturado | Pila de protocolos: {pila}')

        for layer in packet.layers:
            name = layer.layer_name
            desc = LAYER_INFO.get(name, f'Capa desconocida: {name}')
            print(f'    [{name.upper():8}] {desc}')

            # anotaciones específicas por protocolo
            if name == 'icmp' and hasattr(layer, 'type'):
                tipo = str(layer.type)
                significado = ICMP_TYPES.get(tipo, 'Tipo no común')
                print(f'             → Tipo ICMP {tipo}: {significado}')

            if name == 'ip' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                print(f'             → {layer.src} → {layer.dst}  (TTL: {getattr(layer, "ttl", "?")})')

            if name == 'eth' and hasattr(layer, 'src') and hasattr(layer, 'dst'):
                print(f'             → MAC src: {layer.src}  |  MAC dst: {layer.dst}')

            if name == 'tcp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                flags = getattr(layer, 'flags_str', '')
                print(f'             → Puerto {layer.srcport} → {layer.dstport}  flags: {flags}')

            if name == 'udp' and hasattr(layer, 'srcport') and hasattr(layer, 'dstport'):
                print(f'             → Puerto {layer.srcport} → {layer.dstport}')

            if name == 'dns' and hasattr(layer, 'qry_name'):
                print(f'             → Consulta DNS: {layer.qry_name}')

            if name == 'imap' and hasattr(layer, 'request_command'):
                print(f'             ⚠️  Comando IMAP visible: {layer.request_command}')

            print('          Datos de la capa:')
            layer.pretty_print()

        print(f'  {"─" * 56}')

    def __capture_resume(self, capture):
        print('\n  Escuchando la red. Cada línea es un paquete capturado.')
        print('  Pulsa Ctrl+C para detener la captura.\n')
        print(f'  {"─" * 56}')

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
        resumen = '  |  '.join(f'{k}: {v}' for k, v in list(campos.items())[:4])
        print(f'  [GUARDADO] {resumen}')

        if self.monitor_system:
            packet_data['indice'] = 'redes1'
            clase_name = self.project_name.replace(f'{self.base_folder}/', '').replace('.json', '')
            self.monitor_system.send_data(clase_name, packet_data)
            print(f'  [LOGSTASH] Paquete enviado al sistema de monitorización')

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
        sep = '─' * 60
        print(f'\n{sep}')
        print('  ¿QUÉ ES UN SNIFFER?')
        print('  Un sniffer (o analizador de paquetes) captura el tráfico')
        print('  que circula por una interfaz de red. Permite inspeccionar')
        print('  los protocolos y datos de cada comunicación en tiempo real.')
        print(f'{sep}')
        print(f'  Interfaz escuchada : {", ".join(self.interfaces)}')
        ifaces_info = '  (la interfaz es el adaptador de red físico o virtual que recibe los paquetes)'
        print(ifaces_info)
        filtro = self.filters if self.filters else 'ninguno — se captura todo el tráfico'
        print(f'  Filtro BPF activo  : {filtro}')
        print('  (BPF = Berkeley Packet Filter, permite acotar qué paquetes capturar)')
        print(f'  Datos guardados en : {self.project_name}')
        print(f'{sep}\n')
        self.__init_capture()
