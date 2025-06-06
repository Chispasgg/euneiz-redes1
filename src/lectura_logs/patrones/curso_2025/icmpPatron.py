'''
Created on 29 abr. 2025
https://www.bro.org/sphinx/scripts/base/protocols/icmp/main.bro.html
@author: pgg
'''
from lectura_logs.PatronPadre import PatronPadre

class icmpPatron(PatronPadre):
    '''
    Clase patrón del archivo ICMP
    '''
    dict_values = ["layer_name", "type", "code", "checksum",
                   "checksum_status", "ident", "ident_le", "seq", "seq_le","data_time","data_time_relative","data","data_data","data_len"]

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'icmp.log', path_log)

    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        # Filtro especializado para protocolo ICMP
        if 'layers' in data_string: 
            if 'icmp' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['icmp']:
                        resultado[x] = data_string['layers']['icmp'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None
        return resultado