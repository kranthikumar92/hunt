#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import base58
import codecs


def count_lines(file):
	return sum(1 for line in open(file, 'r'))


def convert(file_in,file_out,nom):
    print("===========File input -> " + file_in)
    print("===========File output -> " + file_out)
    i = 0
    line_10 = 100000
    ii = 0
    f = open(file_in,'r')
    fw = open(file_out,'a')
    while i < nom:
        if (i+ii) == nom:
            print("\n Finish")
            break
        if line_10 == i:
            print("Error - {} | Total line -> {}".format(ii,line_10),end='\r')
            line_10 += 100000
        try:
            adr58 = f.readline().strip()
            adr160 = base58.b58decode_check(adr58).hex()[2:]
        except:
            ii +=1
        else:
            #fw.write(hash160+'\n')
            fw.write(adr160+'\n')
            i += 1
    f.close()
    fw.close()


if __name__ == "__main__":

    if len (sys.argv) < 3:
        print ("Ошибка. Слишком мало параметров.")
        sys.exit (1)

    if len (sys.argv) > 3:
        print ("Ошибка. Слишком много параметров.")
        sys.exit (1)

    file_in = sys.argv[1]
    file_out = sys.argv[2]

    line_count = count_lines(file_in)
    print("all lines -> " + str(line_count))
    convert(file_in,file_out,line_count)