# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
from cashaddress import convert


f = open('cash.txt', 'r')
f1 = open('cash-legasy.txt', 'a')
i=1
for line in f:
    #print(line.strip())
    aa = 'bitcoincash:'+line.strip()
    #print(aa)
    addr_ch_l = convert.to_legacy_address(aa.strip())+'\n'
    #print(addr_ch_l)
    f1.write(addr_ch_l)
    i+=1
    print(i,end='\r')


f.close()
f1.close()