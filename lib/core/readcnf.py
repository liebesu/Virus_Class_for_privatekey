__author__ = 'liebesu'
import os
import ConfigParser
from lib.core.constants import CONFPATH
def read_conf():
    """read ida.conf
    """
    config = ConfigParser.ConfigParser()
    config.read(os.path.join(CONFPATH,"scan.conf"))

    inputpath=config.get("Input path","inputpath")
    outputpath=config.get("Output path","outputpath")
    Scantype=config.get("Scan type","type")
    datebaseip=config.get("Datebase","ip")
    datebaseuser=config.get("Datebase","user")
    datebasepsw=config.get("Datebase","password")
    datebasename=config.get("Datebase","databasename")
    datebasetable=config.get("Datebase","tablename")
    md5filename=config.get("MD5 file","md5filename")

    return inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename

def check_config():
    '''check ida.config is exist or not
    '''
    configfile = os.path.join(CONFPATH , 'scan.conf')
    if not os.path.exists(configfile):
        print ("ida.conf file does not exist")
    else:
        print("ida.conf file is exist")
    return True
