#coding=utf-8

import os
import sys
import string
import shutil
from PEfileExtract import PEfileExtract
import PEfileExtract
#import MySQLdb

#sampledir = "./sample" #样本目录
sampledir = "D:/PEFile-win32/win32-2/"
#resultdir = "./result/" #结果目录
resultdir = "D:/Project/MalwareData_Test/result/" #结果目录
# sampledir = "./sample_Light"
# resultdir = "./result_Light/"
configdir = "D:/Project/MalwareData_Test/config/" #设置目录
skiplist = ['.dll', '.DLL', '.txt', '.doc']
extractlist = ['.exe', '.EXE'] #提取后缀列表

###########################################################################################

def clearFileDir(rdir): #清除文件目录
    for root, dirs ,files in os.walk(rdir,topdown = False): #清除目标目录中的文件
        for fn in files:
            os.remove(os.path.join(root, fn))

        for dn in dirs:
            os.rmdir(os.path.join(root, dn))

def initFlist():#
    flist = []

    for parent, dirnames, filenames in os.walk(sampledir): #遍历样本目录
        for f in filenames:
            filetype = os.path.splitext(f)[1] #文件名中提取文件类型

            if(filetype in extractlist): #如果文件类型为exe或者EXE
                flist.append(os.path.join(parent, f)) #拼接文件目录和
            elif(filetype in skiplist):
                pass
            elif(filetype == ''):
                pass
            else:
                flist.append(os.path.join(parent, f))

    return flist

def main():
    if os.path.exists(resultdir): #若结果目录已存在，则清除已有文件目录
        clearFileDir(resultdir)

    flist = initFlist()
    print '\n', '='*50, '\n'
    length = len(flist)
    cnt = 0

    for f in flist:
        cnt = cnt + 1
        print '-'*11,'[extract',str(cnt)+'/'+str(length),']: ',f
        fw = resultdir + (f.split('/' ,2))[2] #拿到最后的文件夹和文件名
        os.makedirs(fw)
        file = PEfileExtract.PEfileExtract(f, fw)
        del file

    print '\n', '='*50, '\n'
    print 'end'

if __name__ == '__main__':
    main()