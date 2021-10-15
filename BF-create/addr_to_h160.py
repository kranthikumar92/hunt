#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import base58
import codecs

def convert(file_in,file_out):
    print("===========File input -> " + file_in)
    print("===========File output -> " + file_out)
    i = 0
    line_10 = 100000
    ii = 0
    count = 0
    f = open(file_in,'r')
    fw = open(file_out,'a')
    while True:
        adr58 = f.readline().strip()
        if not adr58:
            print('Finish!')
            f.close()
            fw.close()
            sys.exit()
        count += 1

        if count == line_10:
            print("skip: {} | pass line: {} | total: {}".format(ii,i,count),end='\r')
            line_10 +=10000

        try:
            adr160 = base58.b58decode_check(adr58).hex()[2:]
        except:
            ii +=1
        else:
            fw.write(adr160+'\n')
            i += 1



if __name__ == "__main__":

    if len (sys.argv) < 3:
        print ("Ошибка. Слишком мало параметров.")
        sys.exit (1)

    if len (sys.argv) > 3:
        print ("Ошибка. Слишком много параметров.")
        sys.exit (1)

    file_in = sys.argv[1]
    file_out = sys.argv[2]

    convert(file_in,file_out)