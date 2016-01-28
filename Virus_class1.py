__author__ = 'liebesu'
import urllib
import urllib2
import json
import re,datetime,os
import MySQLdb
from pprint import pprint
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH,VTAPIKEY,JSONPATH
inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename=read_conf()

def Virus_class():
    apikey='55120838f82de4a041382ffefdeb6b7accac770db1c30edbc76a1cff9418b642'
    base = 'https://www.virustotal.com/vtapi/v2/'
    param = {'resource':md5,'apikey':apikey}
    url = base + "file/report"
    data = urllib.urlencode(param)
    result = urllib2.urlopen(url,data)
    jdata =  json.loads(result.read())

    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)
    allmd5=open(allmd5file,"r").readlines()

    if jdata['response_code'] == 0:
        mark = "Not Found in virustotal"
        virusname="null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"

    else:
        mark = jdata['posjdataives']
        virusname="null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        jsonpath=os.path.join(JSONPATH,md5filename[:-4])
        filejsonpath= os.path.join(jsonpath,md5+".json")
        if os.path.exists(jsonpath):
            jsondumpfile=open(filejsonpath,"w")
            pprint(jdata,jsondumpfile)
            jsondumpfile.close()
        else:
            os.makedirs(jsonpath)
            jsondumpfile=open(filejsonpath,"w")
            pprint(jdata,jsondumpfile)
            jsondumpfile.close()
        sha1=jdata['sha1']
        sha256=jdata['sha256']
        if 'Kaspersky' in jdata['scans'] :
            if jdata['scans']['Kaspersky']['detected']:
                kaspersky_result = jdata['scans']['Kaspersky']['result']
                kaspersky_update = jdata['scans']['Kaspersky']['update']
                kaspersky_version = jdata['scans']['Kaspersky']['version']
                virusname=kaspersky_result
                if "Trojan-" in kaspersky_result:
                    virusname=kaspersky_result.replace('Trojan-','')
                    if "not-a-virus:" in virusname or "HEUR:" in virusname:
                        virusname=virusname.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
                if "not-a-virus:" in kaspersky_result or "HEUR:" in kaspersky_result:
                        virusname=kaspersky_result.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
        if 'ClamAV' in jdata['scans'] :
            if jdata['scans']['ClamAV']['detected']:
                clamav_result = jdata['scans']['ClamAV']['result']
                clamav_update = jdata['scans']['ClamAV']['update']
                clamav_version = jdata ['scans']['ClamAV']['version']
        #print kaspersky_result,kaspersky_update,kaspersky_version,clamav_result,clamav_update,clamav_version,virusname

    db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
    cursor = db.cursor()
    sqltime= datetime.datetime.now()
    #"+"'"+str(md5)+"'"+","
    sql="insert into "+datebasetable+" (Md5,Sha1,Sha256,Virus_Name,Kaspersky,Kaspersky_update,Kaspersky_version,ClamAV,ClamAV_update,\
    ClamAV_version,Mark,Md5File) values( "+"'"+str(md5)+"'"+","+"'"+str(sha1)+"'"+","+"'"+str(sha256)+"'"+","+"'"+str(virusname)+"'"+","+"'"+str(kaspersky_result)+"'"+","+\
        "'"+str(kaspersky_update)+"'"+ ","+ "'"+str(kaspersky_version)+"'"+","+"'"+str(clamav_result)+"'"+","+"'"+\
        str(clamav_version)+"'"+","+"'"+str(clamav_update)+"'"+","+"'"+str(mark)+"'"+","+"'"+str(md5filename)+"'"+")"
    cursor.execute(sql)
    db.commjdata()
    cursor.close()
    db.close()