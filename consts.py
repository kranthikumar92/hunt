# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
import uuid
from bloomfilter import BloomFilter
import platform
import os
import sys
import ctypes
import smtplib, datetime, socket
from mnemonic import Mnemonic
from bip_utils.utils import CryptoUtils
from bip_utils import  P2PKH
from multiprocessing import  Value, Lock, Process
from bip32 import BIP32
from coincurve import PublicKey
import time, argparse
import multiprocessing
import colorama
colorama.init()

class sockets:
    server:str = "188.225.86.188" # iP server statistic
    port:int = 9009 # port serverstatistic

class email:
    host:str = "smtp.timeweb.ru" # SMTP server
    port:int = 25
    password:str = "---------------"
    subject:str = "--- Find Mnemonic ---"
    to_addr:str = "info@quadrotech.ru"
    from_addr:str = "info@quadrotech.ru"
    desc:str = ""

class inf:
    ###############################################################################
    #==============================================================================
    if platform.system().lower().startswith('win'):
        dllfile = 'ice_secp256k1.dll'
        if os.path.isfile(dllfile) == True:
            pathdll = os.path.realpath(dllfile)
            ice = ctypes.CDLL(pathdll)
        else:
            print('File {} not found'.format(dllfile))
        
    elif platform.system().lower().startswith('lin'):
        dllfile = 'ice_secp256k1.so'
        if os.path.isfile(dllfile) == True:
            pathdll = os.path.realpath(dllfile)
            ice = ctypes.CDLL(pathdll)
        else:
            print('File {} not found'.format(dllfile))
        
    else:
        print('[-] Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
        sys.exit()
    ###############################################################################
    #==============================================================================
    ice.privatekey_to_ETH_address.argtypes = [ctypes.c_char_p] # pvk
    ice.privatekey_to_ETH_address.restype = ctypes.c_void_p
    ice.privatekey_to_h160.argtypes = [ctypes.c_int, ctypes.c_bool, ctypes.c_char_p, ctypes.c_char_p]  # 012,comp,pvk,ret
    ice.pbkdf2_hmac_sha512_dll.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int] # ret, words, len
    #==============================================================================
    ice.free_memory.argtypes = [ctypes.c_void_p] # pointer
    #==============================================================================
    ice.init_secp256_lib()
    #==============================================================================
    ###############################################################################

    def privatekey_to_ETH_address(pvk_int):
        ''' Privatekey Integer value passed to function. Output is 20 bytes ETH address lowercase with 0x'''
        pass_int_value = hex(pvk_int)[2:].encode('utf8')
        res = inf.ice.privatekey_to_ETH_address(pass_int_value)
        addr = (ctypes.cast(res, ctypes.c_char_p).value).decode('utf8')
        inf.ice.free_memory(res)
        return '0x'+addr
    #==============================================================================
    def pbkdf2_hmac_sha512_dll(words):
        seed_bytes = (b'\x00') * 64
    #    words = 'good push broken people salad bar mad squirrel joy dismiss merge jeans token wear boring manual doll near sniff turtle sunset lend invest foil'
        inf.ice.pbkdf2_hmac_sha512_dll(seed_bytes, words.encode("utf-8"), len(words))
        return seed_bytes
    def _privatekey_to_h160(addr_type, iscompressed, pvk_int):
        # type = 0 [p2pkh],  1 [p2sh],  2 [bech32]
        pass_int_value = hex(pvk_int)[2:].encode('utf8')
        print(pass_int_value)
        res = (b'\x00') * 20
        inf.ice.privatekey_to_h160(addr_type, iscompressed, pass_int_value, res)
        return res
    def privatekey_to_h160(addr_type, iscompressed, pvk_int):
        res = inf._privatekey_to_h160(addr_type, iscompressed, pvk_int)
        return bytes(bytearray(res))
    #==============================================================================


    version:str = " * Pulsar v4.3.3 multiT Hash160 * "
    #mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese','portuguese','czech']
    mnemonic_lang:list = ['english','japanese','spanish','chinese_simplified']
    bip:str = "32"
    count:int = 1
    th:int = 1 #number of processes
    db_bf:str = ""
    db_puzle:str = ""
    puzle = False
    work_time = 0.0
    mode:str = ""
    mode_text:str = ""
    bit:int = 128
    debug:bool = False
    mail:str = ""
    mail_nom:str = 0
    sockets:str = ""
    sockets_nom:int = 0
    dt_now:str = ""
    uid:uuid
    bf:BloomFilter
    list30:list = []
    l32:list = ["m/0'/","m/44'/0'/"]
    l32_:list = ["","'"]
    l44:list = ["0","145","236"]#["0","145","236","156","177","222","192","2","3","5","7","8","20","22","28","90","133","147","2301","175","216"]
    leth:list = ["60","61"]
    PATHS_44_49:dict = {
        "BTC": {"CODE":"0","PK":b'\x00',"PS":b'\x05'},
        "BCH": "145",
        "BSV": "236",
        "BTG": "156",
        "BTCZ": "177",
        "BITG": "222",
        "LCC": "192",
        "LTC": "2",
        "DOGE": "3",
        "DASH": "5",
        "NMC": "7",
        "FTC": "8",
        "DGB": "20",
        "MONA": "22",
        "VTC": "28",
        "XMY": "90",
        "ZEC": "133",
        "ZCL": "147",
        "QTUM": "2301",
        "RVN": "175",
        "FLO": "216"
    }

class coin_type:

  def __init__(self, name, symbol, public_magic, private_magic, bip32_code, public_key_version, address_prefix, wif_version):
    self.name = name
    self.symbol = symbol
    self.public_magic = public_magic
    self.private_magic = private_magic
    self.bip32_code = bip32_code
    self.public_key_version = public_key_version
    self.address_prefix = address_prefix
    self.wif_version = wif_version

# Bitcoin
btc = coin_type(
  name = "Bitcoin",
  symbol = "btc",
  public_magic = "0488B21E", # xpub
  private_magic = "0488ADE4", # xprv
  bip32_code = "0",
  public_key_version = "00",
  address_prefix = "1",
  wif_version = "80")

# Bitcoin cash
bch = coin_type(
  name = "Bitcoin Cash",
  symbol = "bch",
  public_magic = "0488B21E", # xpub
  private_magic = "0488ADE4", # xprv
  bip32_code = "145",
  public_key_version = "00",
  address_prefix = "1",
  wif_version = "80")

# Litecoin
ltc = coin_type(
  name = "Litecoin",
  symbol = "ltc",
  public_magic = "019DA462", # Ltub
  private_magic = "019D9CFE", # Ltpv
  bip32_code = "2",
  public_key_version = "30",
  address_prefix = "",
  wif_version = "B0")