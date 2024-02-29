'''
Created on 14 jun. 2018

@author: pgg
'''

import logging
import logstash
import sys
import requests
import json
import time


class EnvioDatosLogstash(object):
    '''
    Clase para el envío de datos de log en formato JSON a logstash por TCP
    Por defecto se hace a localhost:5959
    '''
    indexes_increased = {}
    data_options = ['INFO', 'WARNING', 'ERROR']
    res = {data_options[0]:0, data_options[1]:0, data_options[2]:0}
    host = 'localhost'
    port = 5959
    logger = None

    def __init__(self, host=None, port=None):
        '''
        Constructor
        '''
        if host:
            self.host = host
        if port:
            self.port = port
        
        self.logger = logging.getLogger('python-logstash-logger')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(logstash.TCPLogstashHandler(self.host, self.port, version=1))
#         self.logger.addHandler(logstash.LogstashHandler(self.host, self.port, version=1))
        
    def __increase_index_limit(self, index_name, last_time=False):
        if index_name not in self.indexes_increased:
            url = "http://" + str(self.host) + ":9200/bypgg-" + str(index_name) + "/_settings"
            headers = {"Content-Type": "application/json"}
            # visualizacion
            # auth = ('elastic', 'C8dZZgL6EDjT2zdq7bzk')
            auth = ('elastic', 'changeme')
            # monitorizacion
            # auth = ('elastic', 'i9HQ45P8WQ3gd7yPdf')
            data = {"index": {"max_docvalue_fields_search": "10000000", "mapping": {"total_fields": {"limit": "100000"}}}}
            time.sleep(5)
            response = requests.put(url, headers=headers, auth=auth, data=json.dumps(data))
            result = json.loads(response.text)
            if 'acknowledged' in result:
                if result['acknowledged'] == True:
                    print("            STATUS OK: " + str(index_name))
                    self.indexes_increased[index_name] = 1
                else:
                    if last_time:
                        print("        STATUS FAIL 2.1: " + str(result))
                    else:
                        print("        STATUS FAIL 2.0 reintentando")
                        self.__increase_index_limit(index_name, True)
            else:
                if last_time:
                    print("        STATUS FAIL 1.1: " + str(result))
                else:
                    print("        STATUS FAIL 1.0 reintentando")
                    self.__increase_index_limit(index_name, True)
        
    def send_data(self, project_name, data, is_warning=False, is_error=False):
        sended = True
        try:
            if type(data) is dict:
#                 print('=============================================================================')
#                 print(data)
#                 print('=============================================================================')
                if is_error:
                    self.logger.error(project_name, extra=data)
                    self.res[self.data_options[2]] += 1
                elif is_warning:
                    self.logger.warning(project_name, extra=data)
                    self.res[self.data_options[1]] += 1
                else:
                    self.logger.info(project_name, extra=data)
#                     self.logger.info(str(project_name))
                    self.res[self.data_options[0]] += 1
                self.__increase_index_limit(data['indice'])
            else:
                print("datos no son diccionario, no son enviados")
                sended = False
        except:
            print("error al enviar el mensaje a logstash: " + str(sys.exc_info()))
            sended = False
        return sended
    
    def get_sended_info(self):
        return self.res
