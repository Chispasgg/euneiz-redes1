'''
Created on 14 jun. 2018
https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html#type-Conn::Info
lineas 22694356
@author: pgg
'''
from lectura_logs.PatronPadre import PatronPadre


class connPatron(PatronPadre):
    '''
    Clase patron del archivo conn
    '''
    dict_values = ["layer_name", "dst", "dst_resolved", "dst_oui",
                   "dst_oui_resolved", "addr", "addr_resolved", "addr_oui",
                   "addr_oui_resolved", "dst_lg", "lg", "dst_ig", "ig",
                   "src", "src_resolved", "src_oui", "src_oui_resolved", "src_lg", "src_ig", "type"]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'conn.log', path_log)
    
    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False
        
        # filtro especializado en conexion, capa eth
        if 'layers' in data_string:
            if 'eth' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['eth']:
                        resultado[x] = data_string['layers']['eth'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True
        
        if not has_data:
            resultado = None
        return resultado
        
