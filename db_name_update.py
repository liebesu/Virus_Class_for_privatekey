from multiprocessing import Pool
import MySQLdb
import os
import time
from lib.core.readcnf import read_conf
from lib.core.constants import ROOTPATH

__author__ = 'liebesu'


inputpath,outputpath,Scantype,datebaseip,datebaseuser,datebasepsw,datebasename,datebasetable,md5filename,key,newav=read_conf()
def db_name_update(md5):
    try:
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
        cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
        sql="select  * from "+datebasetable+" where Md5='"+md5+"' limit 0,1"
        cursor.execute(sql)
        result=cursor.fetchall()
        cursor.close()
        db.close()
    except:
        time.sleep(5)
        cursor.close()
        db.close()
        db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw)
        cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
        sql="select  * from "+datebasetable+" where Md5='"+md5+"' limit 0,1"
        cursor.execute(sql)
        result=cursor.fetchall()
        cursor.close()
        db.close()
    if result[0]['Virus_Name'] == "null":
        global newname
        newname="null"
        for av in newav:
            if result[0][av] and  "null" not in result[0][av] :
                #print result[0][av]
                newname = av+":"+result[0][av]
                break
        if newname !="null":
            try:
                db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
                cursor = db.cursor(cursorclass=MySQLdb.cursors.DictCursor)
                sql="update "+datebasetable+" set Virus_Name = '"+newname+"' where Md5 ='"+md5+"'"

                cursor.execute(sql)
                db.commit()
                a=cursor.fetchall()

                cursor.close()
                db.close()
            except:
                cursor.close()
                db.close()

            os.system("echo " +md5+ " >> new.txt" )
        else:
            os.system("echo " +md5+ " >> no.txt" )

def allmd5():
    db = MySQLdb.connect(datebaseip,datebaseuser,datebasepsw,datebasename)
    cursor = db.cursor()
    tmpmd5file='/tmp/nomd5'
    if os.path.exists(tmpmd5file):
        os.remove(tmpmd5file)
    md5sql='select Md5 from '+datebasetable+' where Virus_Name ="null" into outfile '+'"'+tmpmd5file+'"'
    cursor.execute(md5sql)
    db.commit()
    cursor.close()
    db.close()
    md5filedir = os.path.join(ROOTPATH,"md5file")
    allmd5file=os.path.join(md5filedir,md5filename)
    os.system("cp /tmp/nomd5 "+allmd5file)
    allmd5=open(allmd5file,"r").readlines()
    allmd5=[md5.replace('\n', '').replace('\r', '') for md5 in allmd5]
    return allmd5

if __name__=="__main__":
    allmd5s=allmd5()
    pool=Pool(processes=100)
    pool.map(db_name_update,allmd5s)
    pool.close()
    pool.join()
    print "finished"