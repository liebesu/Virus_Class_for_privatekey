from multiprocessing import Pool
import MySQLdb
import os
import time
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH

__author__ = 'liebesu'


inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename,key,newav=read_conf()

def db_name_update(md5):
    md5=str(md5)
    try:
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
        sql="select * from "+datebasetable+" where Md5='"+md5+"'"
        cursor.execute(sql)
        result=cursor.fetchall()
        print result
        cursor.close()
        db.close()
    except:
        time.sleep(5)
        cursor.close()
        db.close()
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
        sql="select * from "+datebasetable+" where Md5='"+md5+"'"
        cursor.execute(sql)
        result=cursor.fetchall()
        cursor.close()
        db.close()
    for av in newav.replace('\n', ''):
        if result.Virus_Name == "null":
            print result['Virus_Name']
            if result[av]=='' and  "null" not in result[av] :
                newvirusname=av+":"+result[av]
            break

    db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
    cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
    sql="update "+datebasetable+"set Virus_Name="+newvirusname+" where Md5 ='"+md5+"'"
    cursor.execute(sql)
    cursor.close()
    db.close()
    print "finish"
def allmd5():
    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)
    allmd5=open(allmd5file,"r").readlines()
    allmd5=[md5.replace('\n', '').replace('\r', '') for md5 in allmd5]
    print len(allmd5)
    return allmd5

if __name__=="__main__":
    allmd5s=allmd5()
    pool=Pool(processes=1)
    pool.map(db_name_update,allmd5s)
    pool.close()
    pool.join()
    print "finished"