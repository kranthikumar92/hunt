# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
"""
@author: Noname400
"""
import logging
from logging import Formatter
from bloomfilter import BloomFilter
import platform, os, sys, ctypes, random, time, argparse, multiprocessing
import smtplib, datetime, socket, bitcoin, secrets, hashlib
from mnemonic import Mnemonic
from multiprocessing import  Value, Lock, Process, freeze_support, Queue
from bip32 import BIP32
import requests, string
from random import randint
from colorama import Fore, Back, Style, init
import secp256k1_lib, bitcoin
init()

current_path = os.path.dirname(os.path.realpath(__file__))
logger_found = logging.getLogger('FOUND')
logger_found.setLevel(logging.INFO)
handler_found = logging.FileHandler(os.path.join(current_path, 'found.log'))
handler_found.setFormatter(Formatter(fmt='[%(asctime)s: %(levelname)s] %(message)s'))
logger_found.addHandler(handler_found)

logger_info = logging.getLogger('INFO')
logger_info.setLevel(logging.INFO)
handler_info = logging.FileHandler(os.path.join(current_path, 'info.log'))
handler_info.setFormatter(Formatter(fmt='[%(asctime)s: %(levelname)s] %(message)s'))
logger_info.addHandler(handler_info)

logger_dbg = logging.getLogger('DEBUG')
logger_dbg.setLevel(logging.DEBUG)
handler_dbg = logging.FileHandler(os.path.join(current_path, 'debug.log'))
logger_dbg.addHandler(handler_dbg)

logger_err = logging.getLogger('ERROR')
logger_err.setLevel(logging.DEBUG)
handler_err = logging.FileHandler(os.path.join(current_path, 'error.log'))
handler_err.setFormatter(Formatter(fmt='[%(asctime)s: %(levelname)s] %(message)s'))
logger_err.addHandler(handler_err)

class Counter(object):
    def __init__(self, initval=0):
        self.val = Value(ctypes.c_uint64, initval)
        self.lock = Lock()
    def increment(self):
        with self.lock:
            self.val.value += 1
    def increment4(self):
        with self.lock:
            self.val.value += 4
    def increment2(self):
        with self.lock:
            self.val.value += 2
    def value(self):
        with self.lock:
            return self.val.value

class email:
    host:str = "smtp.timeweb.ru" # SMTP server
    port:int = 25
    password:str = '12qwerty34'
    subject:str = '--- Find Mnemonic ---'
    to_addr:str = 'Ваш адрес'
    from_addr:str = 'hunt@quadrotech.ru'
    desc:str = ''

class inf:
    def load_game():
        try:
            f = open('wl/game.txt','r')
            l = [line.strip() for line in f]
            f.close()
        except:
            logger_err.error('Error load wl/game.txt')
            print(f'[E] Error load wl/game.txt')
            return None
        else:
            return l
    def load_custom(custom_file):
        try:
            f = open(custom_file,'r')
            l = [line.strip() for line in f]
            f.close()
        except:
            logger_err.error(f'Error load {custom_file}')
            print(f'[E] Error load {custom_file}')
            return None
        else:
            return l
    version:str = '* Pulsar v4.10.8 multiT Hash160 *'
    mnemonic_BTC:list = ['english'] # ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese','portuguese','czech']
    mnemonic_ETH:list = ['english'] # ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese','portuguese','czech']
    balance:bool = False
    brain = False
    bal_err:int = 0
    bip:str = '32'
    bal_server:list = ['https://api.blockcypher.com/v1/btc/main/addrs/', 'https://rest.bitcoin.com/v2/address/details/', 'https://sochain.com/api/v2/address/BTC/', \
        'https://blockchain.info/rawaddr/']
    ETH_bal_server:list = ['https://api.blockchair.com/ethereum/dashboards/address/','https://api.etherscan.io/api?module=account&action=balance&address=']
    bal_srv_count:int = 0
    bal_all_err = 0
    count:int = 1
    count_nem = 0
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
    lbtc:list = ['44','49','84']
    l32:list = ["m/0'/","m/44'/0'/"]
    l32_:list = ["","'"]
    l44:list = ['0','145','236'] # ["0","145","236","156","177","222","192","2","3","5","7","8","20","22","28","90","133","147","2301","175","216"]
    leth:list = ['60','61'] #['60','61']