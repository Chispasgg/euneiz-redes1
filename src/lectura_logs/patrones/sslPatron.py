'''
Created on 14 jun. 2018
https://www.bro.org/sphinx/scripts/base/protocols/ssl/main.bro.html#type-SSL::Info
lineas 56214
@author: pgg
'''
from lectura_logs.PatronPadre import PatronPadre


class sslPatron(PatronPadre):
    '''
    Clase patron del archivo ssl
    '''
    dict_values = ['.....']  

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'ssl.log', path_log)
    
    def process_log_data(self, data_string):
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False
        
        # filtro especializado en ssl
        # TODO:
        
        if not has_data:
            resultado = None
        return resultado
