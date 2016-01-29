__author__ = 'liebesu'
import os
from multiprocessing import Pool
global input,outpath,c

input=''
outpath=''
def grep(b):
    a=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    for i in a:
        for j in a:
            cmd="grep '^"+i+j+b+"' "+input +"> " +outpath+i+j+b
            os.system(cmd)
if __name__ == "__main__":
    b=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    pool = Pool(processes=16)
    pool.map(grep,b)
    pool.close()
    pool.join()
    print "finish"