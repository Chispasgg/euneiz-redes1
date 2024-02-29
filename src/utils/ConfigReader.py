'''
Created on 5 nov. 2018

@author: pgg
https://wiki.python.org/moin/ConfigParserExamples
'''
import configparser


class ConfigReader(object):
    '''
    classdocs
    '''
    
    config = None
    
    def __init__(self, config_file):
        '''
        Constructor
        '''
        print('  -> Cargando la configuracion desde ' + config_file)
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        print('  -> Secciones cargadas:')
        print('    => ' + str(self.config.sections()))
        print('-----------------------------------------------------------------')
    
    def getBoolean(self, section, option):
        return self.config.getboolean(section, option)
    
    def getInt(self, section, option):
        return self.config.getint(section, option)
    
    def ConfigSectionMap(self, section):
        dict1 = {}
        options = self.config.options(section)
        for option in options:
            try:
                dict1[option] = self.config.get(section, option)
                if dict1[option] == -1:
                    print("skip: %s" % option)
            except:
                print("exception on %s!" % option)
                dict1[option] = None
        return dict1
