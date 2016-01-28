__author__ = 'liebesu'
import urllib
import urllib2
import json
import re,datetime,os
import MySQLdb
from pprint import pprint
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH,VTAPIKEY,JSONPATH
from multiprocessing import Pool
from multiprocessing import Pool
from multiprocessing.dummy import Pool as ThreadPool
import shutil
inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename=read_conf()
import threading
lock=threading.Lock()
'''def check():
    if scantype=="md5":'''


'''def checkMd5file():

    lists=os.listdir(md5filedir)
    for list in lists:'''




class VTAPI():

    def __init__(self):
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    def getReport(self,md5,apikey):
        param = {'resource':md5,'apikey':apikey}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata

def readMd5file():
    '''apikey=''
    count = 0
    i = 0
    t = 0'''
    '''keyfiles=os.listdir(VTAPIKEY)
    for keyfile in keyfiles:
        ApikeyList = os.path.join(VTAPIKEY,keyfile)
        ApikeyList_object = open(ApikeyList, "r").readlines()
        Apikeycount = len(ApikeyList_object)'''
    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)
    allmd5=open(allmd5file,"r").readlines()
    allmd5=[md5.replace('\n', '').replace('\r', '') for md5 in allmd5]
    return allmd5
    #count = count+1
    #apikey=ApikeyList_object[i].replace('\n','').replace('\r', '')
    '''if count % 4 == 0:
        i=i+1
        apikey = ApikeyList_object[i].replace('\n','').replace('\r', '')
        Apikeycount1=Apikeycount-1
        if i >= Apikeycount1:
            t = t+1
            i = 0'''
def main1(md5):
    apikey='55120838f82de4a041382ffefdeb6b7accac770db1c30edbc76a1cff9418b642'
    parse(vt.getReport(md5,apikey),md5)


def parse(it, md5):
    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)
    if it['response_code'] == 0:
        mark = "Not Found in virustotal"
        virusname="null"
        kaspersky_result = "null"
        kaspersky_update = "null"
        kaspersky_version = "null"
        clamav_result= "null"
        clamav_update = "null"
        clamav_version = "null"

    else:
        mark = it['positives']
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
            pprint(it,jsondumpfile)
            jsondumpfile.close()
        else:
            os.makedirs(jsonpath)
            jsondumpfile=open(filejsonpath,"w")
            pprint(it,jsondumpfile)
            jsondumpfile.close()
        sha1=it['sha1']
        sha256=it['sha256']
        if 'Kaspersky' in it['scans'] :
            if it['scans']['Kaspersky']['detected']:
                kaspersky_result = it['scans']['Kaspersky']['result']
                kaspersky_update = it['scans']['Kaspersky']['update']
                kaspersky_version = it['scans']['Kaspersky']['version']
                virusname=kaspersky_result
                if "Trojan-" in kaspersky_result:
                    virusname=kaspersky_result.replace('Trojan-','')
                    if "not-a-virus:" in virusname or "HEUR:" in virusname:
                        virusname=virusname.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
                if "not-a-virus:" in kaspersky_result or "HEUR:" in kaspersky_result:
                        virusname=kaspersky_result.replace('not-a-virus:','')
                        virusname =virusname.replace('HEUR:','')
        if 'ClamAV' in it['scans'] :
            if it['scans']['ClamAV']['detected']:
                clamav_result = it['scans']['ClamAV']['result']
                clamav_update = it['scans']['ClamAV']['update']
                clamav_version = it ['scans']['ClamAV']['version']
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
    db.commit()
    cursor.close()
    db.close()
    '''lock.acquire()

    cmd="sed -i '/"+md5+"/d' "+allmd5file
    os.system(cmd)
    lock.release()'''

if __name__ == "__main__":
    vt=VTAPI()
    allmd5=readMd5file()
    #print allmd5
    pool = Pool()
    result = pool.map(main1,allmd5)
    pool.close()
    pool.join()




