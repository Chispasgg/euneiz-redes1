'''
Created on 17 jul. 2018

@author: pgg

aumentar el limite de los campos del indice. importante por la cantidad de campos que se recogen de las tramas

curl -XPUT 'localhost:9200/my_index/_settings' -H 'Content-Type: application/json' -d'{"index" : {"mapping" : {"total_fields" : {"limit" : "100000"}}}}'

'''
import pyshark
import json
import os


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

    def __capture_resume(self, capture):
        print("Mostrar Unicamente los datos campturados para analizar")        
        # for packet in capture.sniff_continuously():
        #     print(packet)
        layers_to_check = [
            # # si queremos comprobar las capas que nos interesan
            # # ejemplos son:
            # 'eth',
            # 'http',
            # 'json',
            # 'dns', 
            # 'arp',
            # 'ftp',
            # 'ssh',
            # 'telnet', 
            # 'icmp', 
            # 'vnc',
            # 'smtp'
            ]

        for packet in capture.sniff_continuously():
            print(".", end="")
            for l in packet.layers:
                if len(layers_to_check) > 0:
                    # si hay capas a comprobar, las comprobamos
                    if l.layer_name in layers_to_check:
                        print(f"\n\t Layer to check {l.layer_name}")
                        print(l.pretty_print())
                else:
                    # si no hay capas a comprobar, las mostramos todas
                    print(f"\t Layer to check {l.layer_name}")
                    print(l.pretty_print())
    
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
        
        if self.monitor_system:
            # envio de datos
            packet_data['indice'] = 'redes1'
            clase_name = self.project_name.replace(f'{self.base_folder}/', '').replace('.json', '')  
            self.monitor_system.send_data(clase_name, packet_data) 

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
        print('    => Sniffer de red en ' + str(self.interfaces))
        print('    => Filtro aplicado: ' + str(self.filters))
        print('-----------------------------------------')
        self.__init_capture()
