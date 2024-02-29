'''
Created on 14 jun. 2018
https://www.bro.org/sphinx/script-reference/log-files.html
@author: pgg
'''
from abc import abstractmethod, ABCMeta
import datetime


class PatronPadre(object):
    __metaclass__ = ABCMeta
    
    '''
    Clase padre de los patrones
    '''
    tipo = 'ABSTRACTO_PADRE_PGG'
    path_log = None
    boolean_true_values = ['t', 'tr', 'true']
    boolean_false_values = ['f', 'fa', 'false']
    date_pattern = '%Y-%m-%d_%H:%M:%S'

    def __init__(self, tipo, path_log):
        '''
        Constructor
        '''
        self.tipo = tipo
        self.path_log = path_log
    
    @abstractmethod
    def generate_result_dict_from_pattern_data(self, pattern_data_list):
        result = {}
        for info in pattern_data_list:
            result[info] = ''
        return result 
    
    @abstractmethod
    def process_log_data(self, data_string):
        return {}
    
    @abstractmethod
    def prepare_data_to_send(self, dict_to_send):
        dict_to_send['db_name'] = self.tipo
        for key, value in dict_to_send.items():
            if(isinstance(value, datetime.datetime)):
                dict_to_send[key] = value.strftime(self.date_pattern)
        return dict_to_send
    
    @abstractmethod
    def change_date_to_string(self, date_value):
        return date_value.strftime(self.date_pattern)
    
    @abstractmethod
    def get_date_from_int(self, data):
#         data = (data / 1000)
#         return datetime.datetime.fromtimestamp(data / 1e3)
        return datetime.datetime.fromtimestamp(data)
    
    @abstractmethod
    def enrich_processed_log_data(self, resultado):
        self.process_empty_log_data(resultado, self.dict_values)
        try:
            resultado[self.dict_values[0]] = self.get_date_from_int(resultado[self.dict_values[0]])
        except:
            print('posicion 0 no es date en long')
        
        return resultado
    
    @abstractmethod
    def process_empty_log_data(self, log_dict, log_list):
        for key in log_list:
            value_to_check = log_dict[key].lower() 
            
            if ((value_to_check == '') or (value_to_check == '-')):
                # value is missing
                log_dict[key] = None
            elif(value_to_check in self.boolean_false_values):
                # value is boolean FALSE
                log_dict[key] = False
            elif(value_to_check in self.boolean_true_values):
                # value is boolean TRUE
                log_dict[key] = True
            else:
                # value is a number
                try:
                    new_value = float(log_dict[key])
                    if new_value.is_integer():
                        new_value = int(new_value)
                    log_dict[key] = new_value
                except:
                    pass
        return log_dict
