#coding=utf-8

import os
import sys
import string
import shutil
import MySQLdb
import re
import pefile
import time

sampledir = "./sample"
resultdir = "./result/"
# sampledir = "./sample_Light"
# resultdir = "./result_Light/"
configdir = "./config/"
skiplist = ['.dll', '.DLL', '.txt', '.doc']
extractlist = ['.exe', '.EXE']

LONG_STRING_MINSIZE = 8
MEANING_STRING_MINSIZE = 4
PATH_STRING_MINSIZE = 8
MEANING_SPACE_MINCOUNT = 3
STRING_EXTRACT_MAXSIZE = 800
SYMBOL_RATE = 1.9

def initConfig(filename):
    list = []
    with open(configdir+filename,"r") as file:
        for line in file.readlines():
            if line[0] == '#':
                continue
            list2 = []
            list2.append(line[:-1])
            list.append(list2)
    return list



list_noise = []
with open(configdir+'noise.txt','r') as file:
    for line in file.readlines():
        if line[0] == '#':
            continue
        list_noise.append(line[:-1])
list_decode = []
with open(configdir+'decode.txt','r') as file:
    for line in file.readlines():
        if line[0] == '#':
            continue
        list_decode.append(line[:-1])

###########################################################################################

RE_email = re.compile(r'[a-zA-Z][0-9a-zA-Z\-\_\.]*@[\w_\-]+\.\w\w+')
RE_http = re.compile(r'(.?[hH]ttp(s?)://*)|'
                     r'(.*?\.([hH][tT][mM][lL]|[cC][oO][mM]$|[nN][eE][tT]|[oO][rR][gG])+)|'
                     r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)|'
                     r'(.*?\..*?\.[a-zA-Z]{2}(\/\w+)?$)')
RE_diskPath = re.compile(r'[a-zA-Z]:\\+\w*')
RE_path = re.compile(r'((.*?[^\\\?\/\*\|<>:"]+\\)+[^\\\?\/\*\|<>:"])|'
                     r'(.*?\/?([aA]pplication|[uU]sers|src)\/.*?)')
RE_par = re.compile(r'\\par$')
RE_file2e = re.compile(r'.*?\.([eE][xX][eE]|[dD][lL][lL]|[dD][rR][vV]|'
                       r'[jJ][pP][eE]?[gG]|[gG][iI][fF]|[Bb][mM][Pp]|[pP][nN][gG]|'
                       r'[tT][xX][tT]|[iI][nN][iI]|'
                       r'[dD][aA][tT][aA]|misc|sys|php|reloc|rar|zip|7z|tmp|'
                       r'[cC][pP]?[pP]?$|'
                       r'[bB][aA][tT]|manifest)+.*?')
RE_copyright = re.compile(r'(.*?[cC][oO][pP][yY][rR][iI][gG][hH][tT].*?)|'
                          r'(.*?\(c\).*?)|'
                          r'(.*?([cC][oO]|[cC][oO][rR][pP]|[Ll][tT][dD]|'
                          r'[iI][nN][cC]|[lL][lL][cC]|[lL][lL][pP])\..*?)')
RE_version = re.compile(r'((.*?)[vV]ersion(([ ]\d+)|=").*?)|'
                        r'(.*?[vV]([ ]?)\d{1,3}\.\d+.*?)|'
                        r'(.*?[\/\_]\d{1,3}\.\d+.*?)|'
                        r'(.*?(ISO|PKI)\-\d+.*?)|'
                        r'(\d{1,3}\.\d{1,4}\.\d+.*?)')
RE_char = re.compile(r'\w')
RE_pathChar = re.compile(r'[a-zA-Z\\]')
RE_api = re.compile(r'.*?(On[A-Z]|cl[A-Z]|cr[A-Z]|pm[A-Z]|Max[A-Z]|Min[A-Z]|Parent[A-Z]|Show[A-Z]|[a-z]Found|'
                    r'Server[A-Z]|[a-z]Server).*?')

RE_pe_date = re.compile(r'\[\w{3} \w{3}[ \d]{3} \d{2}:\d{2}:\d{2} \d{4} \w+?\]')
RE_year = re.compile(r' ?(19|20)\d{2} ?')
RE_time = re.compile(r'.*?(( ?\d{1,2}\:\d{2} )|[tT]ime[sS]tamp[^i]|\d{12}Z0?).*?')

###########################################################################################

def isVisible(c):
    if ord(c) > 31:
        if ord(c) < 127:
            return True
    else:
        return False

def isNoise(str):
    for line in list_noise:
        if line in str:
            return True
    return False

class PEfileExtract(object):
    def __init__(self, f, fw):
        self.initList(fw)
        self.initFile(f, fw)
        print 'extract start time:', time.asctime(time.localtime(time.time()))
        t1 = time.clock()
        self.pefileExtractFile(f,fw)
        self.meowExtractFile()
        t2 = time.clock()
        print 'extract finished time: ' + str(t2-t1) + ' s'
        self.initWriteFile(fw)
        self.writeFile()
        t3 = time.clock()
        print 'write file finished time: ' + str(t3-t2) + ' s'
        self.closeFile()

    def __del__(self):
        # print 'del'
        pass

    def initList(self, fw):
        self.list_file = []
        self.initConfigList()
        self.list_rawVisible = []
        self.list_uniqueVisible = []
        self.list_longString = []
        self.list_email = []
        self.list_http = []
        self.list_file2e = []
        self.list_path = []
        self.list_unkownString = []
        self.list_copyright = []
        self.list_by = []
        self.list_version = []
        self.list_meaningString = []
        self.list_noMeaningString = []
        self.list_called = []
        self.list_name = []
        self.list_api = []
        self.list_year = []
        self.list_pe_string = []
        self.list_pe_date = []
        self.list_pe_importDll = []
        self.list_pe_importDllName = []
        self.list_filetype = []
        self.list_pe_export = []
    def initConfigList(self):
        self.list_config_keyWord = initConfig('keyWord.txt')
        self.list_config_apiCommon2Skip = initConfig('apiCommon.txt')
        self.list_config_notKeyWord = initConfig('notKeyWord.txt')
        self.list_config_name = initConfig('name.txt')
        self.list_config_noise = []
        self.cnt_skip = 0
        self.cnt_skip2 = 0
        self.cnt_keyWord = 0
        self.cnt_filetype = 0
    def initFile(self, f, fw):
        t = self.file = open(f,'rb')
        self.list_file.append(t)
    def initWriteFile(self,fw):
        # t = self.file_original = open(fw + '/originalfile.exe','w')
        # self.list_file.append(t)
        t = self.file_pefile = open(fw + '/13.pefile.txt', 'w')
        self.list_file.append(t)
        num = len(self.list_pe_string)+len(self.list_pe_date)+len(self.list_pe_importDllName)+len(self.list_pe_importDll)+len(self.list_pe_export)
        t = self.file_pefileInfo = open(fw + '/6.pefileInfo_'+str(num)+'.txt', 'w')
        self.list_file.append(t)
        t = self.file_rawVisible = open(fw + '/0.rawVisible_'+str(len(self.list_rawVisible))+'.txt','w')
        self.list_file.append(t)
        t = self.file_uniqueVisible = open(fw + '/1.uniqueVisible_'+str(len(self.list_uniqueVisible))+'.txt','w')
        self.list_file.append(t)
        t = self.file_longString = open(fw + '/8.longString_'+str(len(self.list_longString))+'.txt','w')
        self.list_file.append(t)
        t = self.file_meaningString = open(fw + '/7.meaningString_'+str(len(self.list_meaningString))+'.txt','w')
        self.list_file.append(t)
        num = len(self.list_path)+len(self.list_http)+self.cnt_filetype+len(self.list_email)
        t = self.file_special = open(fw + '/2.special_'+str(num)+'.txt','w')
        self.list_file.append(t)
        t = self.file_unkownString = open(fw + '/12.UnknownString_'+str(len(self.list_unkownString))+'.txt','w')
        self.list_file.append(t)
        num = len(self.list_by) + len(self.list_copyright) + len(self.list_version) + len(self.list_called) + len(self.list_year)
        t = self.file_otherInfo = open(fw + '/3.otherInfo_'+str(num)+'.txt','w')
        self.list_file.append(t)
        t = self.file_noMeaningString = open(fw + '/11.noMeaningString_'+str(len(self.list_noMeaningString))+'.txt','w')
        self.list_file.append(t)
        t = self.file_skip = open(fw + '/9.skip_'+str(self.cnt_skip+len(self.list_api))+'.txt','w')
        self.list_file.append(t)
        t = self.file_skip2 = open(fw + '/10.skip2_'+str(self.cnt_skip2)+'.txt','w')
        self.list_file.append(t)
        t = self.file_name = open(fw + '/5.name_'+str(len(self.list_name))+'.txt','w')
        self.list_file.append(t)
        t = self.file_keyWord = open(fw + '/4.keyWord_'+str(self.cnt_keyWord)+'.txt','w')
        self.list_file.append(t)
    def writeFile(self):
        # self.file_original.write(self.file.read())
        if self.pefileMark:
            self.file_pefile.write(str(self.pe))
            self.file_pefileInfo.write('\n' + '=' * 30 + ' hash ' + '=' * 30 + '\n' + str(self.hash) + '\n')
            self.writePefileInfo('Date', self.list_pe_date)
            self.file_pefileInfo.write(
                '\n' + '=' * 30 + ' Export(' + str(len(self.list_pe_export)) + ')' + '=' * 30 + '\n')
            self.list_pe_export.sort(key=lambda x: (x[0]))
            for list in self.list_pe_export:
                self.file_pefileInfo.write(list[1] + '\n')
            self.writePefileInfo('ImportDll', self.list_pe_importDll)
            self.writePefileInfo('String', self.list_pe_string)
            self.list_pe_importDllName.sort()
            self.writePefileInfo('ImportDllName', self.list_pe_importDllName)
            self.pe.close()
        else:
            self.file_pefile.write('error.')
        self.write(self.file_rawVisible, self.list_rawVisible)
        self.write(self.file_uniqueVisible, self.list_uniqueVisible)
        self.list_longString.sort(key=lambda x:(-x.count(' '),x))
        self.write(self.file_longString, self.list_longString)
        self.write(self.file_meaningString, self.list_meaningString)
        self.writeSp('Email', self.list_email)
        self.writeSp('Http', self.list_http)
        self.file_special.write('\n' + '='*30 +' File('+str(self.cnt_filetype)+') ' + '='*30 + '\n')
        self.list_filetype.sort(key=lambda x:(x[0]))
        for list in self.list_filetype:
            if len(list) > 1:
                self.file_special.write('-'*10 +'['+list[0]+']'+'-'*10 + '\n')
                for t in list[1:]:
                    self.file_special.write(t+'\n')
        self.list_path.sort(key=lambda x:(-len(x),x))
        self.writeSp('Path', self.list_path)
        self.writeInfo('Copyright', self.list_copyright)
        self.writeInfo('by',self.list_by)
        self.writeInfo('Version', self.list_version)
        self.writeInfo('called', self.list_called)
        self.list_year.sort(key=lambda x:(-len(x)))
        self.writeInfo('time', self.list_year)
        self.list_unkownString.sort(key=lambda x:(-len(x)))
        self.write(self.file_unkownString, self.list_unkownString)
        self.list_noMeaningString.sort(key=lambda x:(-len(x)))
        self.write(self.file_noMeaningString, self.list_noMeaningString)
        self.writeSkip('API(On?)',self.list_api)
        for list in self.list_config_apiCommon2Skip:
            if len(list)>1:
                self.writeSkip(list[0],list[1:])
        for list in self.list_config_notKeyWord:
            if len(list)>1:
                self.writeSkip2(list[0],list[1:])
        for list in self.list_config_keyWord:
            if len(list)>1:
                self.writeKeyWord(list[0],list[1:])
        self.write(self.file_name,self.list_name)

    def addList(self, str):
        self.list_rawVisible.append(str)
        if len(str) < MEANING_STRING_MINSIZE:
            return
        if str in self.list_uniqueVisible:
            return
        self.list_uniqueVisible.append(str)
        if len(str) > STRING_EXTRACT_MAXSIZE:
            self.list_longString.append(str)
            return
        if str in self.list_pe_importDllName:
            return

        mark = True
        l = str.split(' ')
        for s in l:
            if RE_email.search(s):
                self.list_email.append(str)
                mark = False
            elif RE_http.search(s):
                self.list_http.append(str)
                mark = False
            else :
                if RE_file2e.search(s):
                    self.cnt_filetype = self.cnt_filetype + 1
                    t = s.split('.')[1].lower()
                    for type in self.list_filetype:
                        if t == type[0]:
                            type.append(str)
                            mark = False
                    if mark:
                        list = [t]
                        list.append(str)
                        self.list_filetype.append(list)
                        mark = False
                if len(s) >= PATH_STRING_MINSIZE:
                    if RE_path.search(s) or RE_diskPath.search(s):
                        if RE_pathChar.search(s[0]):
                            if isNoise(s):
                                self.list_noMeaningString.append(str)
                                return
                            elif not RE_par.search(str):
                                self.list_path.append(str)
                                mark = False
                        else:
                            self.list_noMeaningString.append(str)
                            return
            if RE_year.search(str):
                if str[1] == ' ' and RE_char.search(str[0]):
                    continue
                elif str not in self.list_year:
                    self.list_year.append(str)
            if 'called' in s:
                self.list_called.append(str)
                mark = False
            if mark:
                break

        if RE_copyright.search(str):
            self.list_copyright.append(str)
            for list in self.list_config_name:
                if list[0] in str:
                    if ('Sample' in str) or ('Old' in str) or ('Alt' in str) or ('NickName' in str) or (
                        'Other' in str) or ('Nickname' in str):
                        continue
                    self.list_name.append(str)
        elif (' by ' in str) or (' By ' in str) or (' By ' in str) :
            self.list_by.append(str)
            for list in self.list_config_name:
                if list[0] in str:
                    if ('Sample' in str) or ('Old' in str) or ('Alt' in str) or ('NickName' in str) or (
                        'Other' in str) or ('Nickname' in str):
                        continue
                    self.list_name.append(str)
        elif RE_version.search(str):
            if not re.match('.*?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?',str):
                if str not in self.list_version:
                    self.list_version.append(str)
        elif RE_time.search(str):
            if str not in self.list_year:
                self.list_year.append(str)
        else:
            cnt = 0
            for i in str:
                if RE_char.match(i):
                    cnt = cnt + 1
            if cnt > 0:
                if float(len(str)) / float(cnt) >= SYMBOL_RATE:
                    self.list_noMeaningString.append(str)
                    return
            if mark:
                mark = True
                for list in self.list_config_keyWord:
                    if list[0] in str:
                        list.append(str)
                        self.cnt_keyWord = self.cnt_keyWord + 1
                        mark = False
                        break
                if str in self.list_pe_string:
                    return
                if str.count(' ') >= MEANING_SPACE_MINCOUNT:
                    self.list_meaningString.append(str)
                elif isNoise(str):
                    self.list_noMeaningString.append(str)
                elif mark:
                    if RE_api.search(str):
                        self.list_api.append(str)
                        return
                    for list in self.list_config_apiCommon2Skip:
                        if list[0] in str:
                            list.append(str)
                            self.cnt_skip = self.cnt_skip + 1
                            return
                    for list in self.list_config_notKeyWord:
                        if list[0] in str:
                            list.append(str)
                            self.cnt_skip2 = self.cnt_skip2 + 1
                            return
                    for list in self.list_config_name:
                        if list[0] in str:
                            if ('Sample' in str) or ('Old' in str) or ('Alt' in str) or ('NickName' in str) or ('Other' in str) or ('Nickname' in str):
                                continue
                            self.list_name.append(str)
                            return
                    if len(str) > LONG_STRING_MINSIZE:
                        if str[0] >= '0' and str[0] <= '9':
                            self.list_noMeaningString.append(str)
                        else:
                            self.list_longString.append(str)
                    else:
                        self.list_unkownString.append(str)

    def meowExtractFile(self):
        d = self.file.read()
        print 'FileLength: ',len(d)
        # data = self.decode(d)
        data = d

        mark = True
        list = []
        cnt = 0
        for i in data:
            cnt = cnt+1
            if isVisible(i) == True:
                list.append(i)
                mark = True
            elif mark:
                mark = False
                str = "".join(list)
                # print cnt,str
                self.addList(str)
                list = []
            else:
                pass
    def pefileExtractFile(self,f,fw):
        self.pefileMark = False
        try:
            self.pe = pefile.PE(f)

            # hash
            self.hash = self.pe.get_imphash()

            # date
            list = RE_pe_date.findall(str(self.pe))
            for i in list:
                if i == '[Thu Jan  1 00:00:00 1970 UTC]':
                    continue
                if i not in self.list_pe_date:
                    self.list_pe_date.append(i)

            # string resource
            try:
                lstring = self.pe.get_resources_strings()
                for s in lstring:
                    self.list_pe_string.append(str(s))
            except:
                print 'error: get_resources_strings error.'
                
            # import
            try:
                for importdll in self.pe.DIRECTORY_ENTRY_IMPORT:
                    if importdll.dll not in self.list_pe_importDll:
                        self.list_pe_importDll.append(importdll.dll)
                        for i in importdll.imports:
                            self.list_pe_importDllName.append(str(i.name))
            except:
                print 'error: pe.DIRECTORY_ENTRY_IMPORT error.'

            # export
            try:
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        self.list_pe_export.append([exp.ordinal, exp.name])
            except:
                print 'error: pe.DIRECTORY_ENTRY_EXPORT error.'

            self.pefileMark = True
        except:
            print 'error: pefile_Extract_File error.'

    def write(self, path, list):
        for s in list:
            path.write(s+'\n')
    def writeSp(self, type, list):
        self.file_special.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_special,list)
    def writeInfo(self, type, list):
        self.file_otherInfo.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_otherInfo,list)
    def writeSkip(self, type, list):
        self.file_skip.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_skip,list)
    def writeSkip2(self, type, list):
        self.file_skip2.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_skip2,list)
    def writeKeyWord(self, type, list):
        self.file_keyWord.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_keyWord,list)
    def writePefileInfo(self, type, list):
        self.file_pefileInfo.write('\n' + '='*30 +' '+ type +'('+ str(len(list)) + ') ' + '='*30 + '\n')
        self.write(self.file_pefileInfo,list)
    def decode(self,str):
        mark = True
        for type in list_decode:
            try :
                data = str.decode(type)
                print 'EncodeType: ', type
                return data
            except:
                pass
        print 'EncodeType: ASCII (Default)'
        return str
    def closeFile(self):
        for f in self.list_file:
            f.close()

def clearFileDir(rdir):
    for r, d ,f in os.walk(rdir,topdown=False):
        for fn in f:
            os.remove(os.path.join(r,fn))
        for dn in d:
            os.rmdir(os.path.join(r,dn))
def initFlist():
    flist = []
    for parent, dirnames, filenames in os.walk(sampledir):
        for f in filenames:
            filetype = os.path.splitext(f)[1]
            if(filetype in extractlist):
                flist.append(os.path.join(parent, f))
            elif(filetype in skiplist):
                pass
            elif(filetype == ''):
                pass
            else:
                flist.append(os.path.join(parent, f))
    return flist

def main():
    if os.path.exists(resultdir):
        clearFileDir(resultdir)
    flist = initFlist()
    print '\n', '='*50, '\n'
    length = len(flist)
    cnt = 0
    for f in flist:
        cnt = cnt + 1
        print '-'*11,'[extract',str(cnt)+'/'+str(length),']: ',f
        fw = resultdir + (f.split('/',2))[2]
        os.makedirs(fw)
        file = PEfileExtract(f,fw)
        del file
    print '\n', '='*50, '\n'
    print 'end'

if __name__ == '__main__':
    main()
