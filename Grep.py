__author__ = 'liebesu'
import os
path=
input=
a=[0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f]
for i in a:
    for j in a:
        cmd="grep '^"+i+j+"' "+input +"> " + path+i+j
        os.system(cmd)
