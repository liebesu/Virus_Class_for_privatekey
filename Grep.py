__author__ = 'liebesu'
import os
input='/polydata/content/malware/md5/md5-info.sys'
outpath='/polydata/content/malware/md5/info4096/'
a=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
for i in a:
    for j in a:
        for m in a:
            cmd="grep '^"+i+j+m+"' "+input +"> " +outpath+i+j+m
            os.system(cmd)