'''
Created on 14 jun. 2018
@author: pgg
'''
from lectura_logs.PatronPadre import PatronPadre


class pcapLivePatron(PatronPadre):
    '''
    Clase patron de la captura pacp en formato live
    '''

    def __init__(self, path_log):
        '''
        Constructor
        '''
        PatronPadre.__init__(self, 'pcap_live', path_log)
    
    def process_log_data(self, data_string):
        data_string['db_name'] = self.tipo
        return data_string
        
