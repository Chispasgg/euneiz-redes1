'''
Created on 29 abr. 2025
https://www.bro.org/sphinx/scripts/base/protocols/imap/main.bro.html
@author: pgg
'''

from lectura_logs.PatronPadre import PatronPadre

class imapPatron(PatronPadre):
    """
    Clase patrón para el protocolo IMAP
    """
    dict_values = [
        "layer_name", "isrequest", "line", "request", "request_tag", "tag", "request_command", "command", "request_username", "request_password"
    ]

    def __init__(self, path_log):
        """
        Constructor
        """
        super().__init__('imap.log', path_log)

    def process_log_data(self, data_string):
        """
        Procesa una entrada del log y devuelve un diccionario con los datos relevantes
        """
        resultado = self.generate_result_dict_from_pattern_data(self.dict_values)
        resultado['db_name'] = self.tipo
        has_data = False

        # Filtro especializado para protocolo IMAP
        if 'layers' in data_string:
            if 'imap' in data_string['layers']:
                for x in resultado.keys():
                    if x in data_string['layers']['imap']:
                        resultado[x] = data_string['layers']['imap'][x].replace('LayerFieldsContainer:', '').strip()
                        has_data = True

        if not has_data:
            resultado = None

        return resultado