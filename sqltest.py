__author__ = 'liebesu'
import MySQLdb

db = MySQLdb.connect("localhost","root","polydata","virusname" )
cursor = db.cursor()
cursor.execute("INSERT INTO `Virus_Class_TEST` VALUES ('1', null, '0b8596e950933abf989458999f88c47b',\
 'AdWare.NSIS.Adload.t', 'not-a-virus:AdWare.NSIS.Adload.t', null,\
 '/polylab/virus_samples_to_xia_051010_class/vt/kaspersky/not-a-virus/AdWare/NSIS/Adload/t/0b8596e950933abf989458999f88c47b.vir');")

db.close()