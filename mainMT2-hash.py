# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-

import sys,time,argparse
import multiprocessing,hashlib,codecs,secrets,smtplib
from multiprocessing import Process
from bip_utils import  Bip44, Bip44Coins, Bip44Changes, Bip49, Bip32
from bip_utils.utils import CryptoUtils
from bloomfilter import BloomFilter
from mnemonic import Mnemonic
from colorama import init, Fore
init()


def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string


def public_to_address(public_key,net_byte:bytes):
    public_key_bytes = codecs.decode(public_key, 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = net_byte#b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = base58(address_hex)
    return wallet


class email:
    host:str = 'smtp.timeweb.ru'
    port:int = 25
    password:str = '-------------'
    subject:str = '--- Find Mnemonic ---'
    to_addr:str = 'info@quadrotech.ru'
    from_addr:str = 'info@quadrotech.ru'
    des_mail = ''


class inf:
    version:str = ' Pulsar v3.6.1 multiT Hash160'
    #mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese']
    #mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french']
    mnemonic_lang = ['english']
    count_32:int = 0
    count_44:int = 0
    count_49:int = 0
    process_count_work:int = 0 #number of processes
    type_bip:int = 0
    dir_bf:str = ''
    process_time_work = 0.0
    mode = ''
    mode_text = ''
    key_found = 0
    words = 0
    debug:int = 0


def load_BF(bf_file):
    BF_:BloomFilter
    try:
        fp = open(inf.dir_bf+'/'+bf_file, 'rb')
    except FileNotFoundError:
        print('\n'+'File: '+ bf_file + ' not found.')
        sys.exit()
    else:
        BF_ = BloomFilter.load(fp)
        print('Bloom Filter '+bf_file+' Loaded')
    return BF_


def load_btc30(file):
    BTC30_:list
    try:
        fp = open(inf.dir_bf+'/'+file, 'r')
    except FileNotFoundError:
        print('\n'+'File: btc30.h160 not found.')
        sys.exit()
    else:
        lines = fp.readlines()
        BTC30_ = [line.rstrip('\n') for line in lines]
        fp.close()
        print('File address pazzle BTC~30 Loaded.')
    return BTC30_


def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=int, help='32, 44, 49 default bip32', default='32')
    parser.add_argument ('-d', '--dir_bf', action='store', type=str, help='directories to BF', default='BF')
    parser.add_argument ('-t', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode', default='s')
    parser.add_argument ('-c', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-w', '--words', action='store', type=int, help='words 12, 24', default=12)
    parser.add_argument ('-e', '--debug', action='store', type=int, help='debug 0 1 2', default=0)
    return parser.parse_args().bip, parser.parse_args().dir_bf, parser.parse_args().threading, parser.parse_args().mode, parser.parse_args().desc, parser.parse_args().words, parser.parse_args().debug


def send_email(text):
    email.subject = email.subject + ' description -> ' + email.des_mail
    BODY:str = '\r\n'.join(('From: %s' % email.from_addr, 'To: %s' % email.to_addr, 'Subject: %s' % email.subject, '', text)).encode('utf-8')
    try:
        server = smtplib.SMTP(email.host,email.port)
    except (ConnectionRefusedError, ConnectionError) as err:
        print("[*] could not connect to the mail server")
    else:
        server.login(email.from_addr, email.password)
        try:
            server.sendmail(email.from_addr, email.to_addr, BODY)
        except UnicodeError:
            print('[*] Error Encode UTF-8')
        else:
            server.quit()


def save_rezult(text:str):
    try:
        f_rez = open('rezult.txt', 'a', encoding='utf-8')
    except FileNotFoundError:
        print('\n'+'file rezult.txt not found.')
    else:
        try:
            tf:str = text+'\n'
            f_rez.write(tf)
        except UnicodeError:
            print('\n'+'Error Encode UTF-8')
        finally:
            f_rez.close()


def work32(bf_work_32,mode,words,debug,list_btc):
    inf.count_32 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        if debug==1:
            mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
            print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
            print('Debug SEED : '+ str(seed_bytes))
        if debug==2:
            print('Debug Mnemonic : '+mnemonic)
            print('Debug SEED : '+ str(seed_bytes))
    	#-----------------------------------------------------------------------------------------------------------------
        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0/" + str(num))  # m/0/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0/" + str(num)))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0/" + str(num)+"'")  # m/0/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0/" + str(num)+"'"))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/" + str(num))  # m/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/" + str(num)))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/" + str(num)+"'")  # m/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/" + str(num)+"'"))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/0/" + str(num))  # m/0'/0/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/0/" + str(num)))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/0/" + str(num)+"'")  # m/0'/0/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/0/" + str(num)+"'"))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/0'/" + str(num))  # m/0'/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/0'/" + str(num)))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/0'/0'/" + str(num)+"'")  # m/0'/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/0'/0'/" + str(num)+"'"))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/44'/0'/0'/" + str(num))  # m/44'/0'/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/44'/0'/0'/" + str(num)))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx = Bip32.FromSeedAndPath(seed_bytes, "m/44'/0'/0'/" + str(num)+"'")  # m/44'/0'/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* Debug Mnemonic : '+mnemonic)
                print('* Public RawCompressed - {}'.format(bip32_ctx.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip32_ctx.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip32_h160_1))
                print('* hash Uncompress - {}'.format(bip32_h160_2))
                print('* Path - {}'.format("m/44'/0'/0'/" + str(num)+"'"))
                print('* address Compress - {}'.format(bip32_ctx.PublicKey().ToAddress()))
            if any(element in bip32_h160_1 for element in list_btc) or any(element in bip32_h160_2 for element in list_btc):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip32_h160_1 in bf_work_32) or (bip32_h160_2 in bf_work_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx.PrivateKey().ToWif()
                bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


def work44(bf_work_44,mode,words,debug,list_btc):
    inf.count_44 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        if debug==1:
            mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
            print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
            print('Debug SEED : '+ str(seed_bytes))
        if debug==2:
            print('Debug Mnemonic : '+mnemonic)
            print('Debug SEED : '+ str(seed_bytes))

        # btc
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if any(element in bip44_hc for element in list_btc) or any(element in bip44_huc for element in list_btc) or any(element in bip44_hc_b for element in list_btc) or any(element in bip44_huc_b for element in list_btc):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # btc_cash
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_CASH)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN_CASH - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if any(element in bip44_hc for element in list_btc) or any(element in bip44_huc for element in list_btc) or any(element in bip44_hc_b for element in list_btc) or any(element in bip44_huc_b for element in list_btc):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BITCOIN_CASH PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BITCOIN_CASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


#        # ltc
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.LITECOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("LITECOIN - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'30')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'30')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'30')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'30')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / LITECOIN'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


#        # DASH
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.DASH)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("DASH - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'4C')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'4C')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'4C')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'4C')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / DASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


#        # DOGE
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.DOGECOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("DOGECOIN - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'1E')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'1E')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'1E')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'1E')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / DOGECOIN'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


#        # sv
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_SV)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip44_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_44 = inf.count_44 + 1
        
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN_SV - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip44_hc_b))
                print('* hash Uncompress begin - {}'.format(bip44_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip44_hc))
                print('* hash Uncompress - {}'.format(bip44_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if any(element in bip44_hc for element in list_btc) or any(element in bip44_huc for element in list_btc) or any(element in bip44_hc_b for element in list_btc) or any(element in bip44_huc_b for element in list_btc):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BITCOIN_SV PAZZLE !!!!!!!!!!!!!'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
            if (bip44_hc_b in bf_work_44) or (bip44_huc_b in bf_work_44) or (bip44_hc in bf_work_44) or (bip44_huc in bf_work_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                bip_addr = public_to_address(bip_obj_chain.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr2 = public_to_address(bip_obj_chain.PublicKey().RawUncompressed().ToHex(),b'00')
                bip_addr3 = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr4 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),b'00')
                res =bip_addr4+ ' | ' +bip_addr3 + ' | ' +bip44_hc +' | '+bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 +' | TRUE | '+ mnemonic +' | '+ bip44_PK +' | BIP 44 / BITCOIN_SV'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
                


def work49(bf_49,mode,words,debug):
    inf.count_49 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        if debug==1:
            mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
            print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
            print('Debug SEED : '+ str(seed_bytes))
        if debug==2:
            print('Debug Mnemonic : '+mnemonic)
            print('Debug SEED : '+ str(seed_bytes))

        # btc 49
        bip_obj_mst = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip49_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip49_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_49 = inf.count_49 + 1
        
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip49_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip49_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip49_hc_b))
                print('* hash Uncompress begin - {}'.format(bip49_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip49_hc))
                print('* hash Uncompress - {}'.format(bip49_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / BITCOIN'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # ltc 49
        bip_obj_mst = Bip49.FromSeed(seed_bytes, Bip44Coins.LITECOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip49_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip49_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_49 = inf.count_49 + 1
        
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip49_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip49_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("LITECOIN - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip49_hc_b))
                print('* hash Uncompress begin - {}'.format(bip49_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip49_hc))
                print('* hash Uncompress - {}'.format(bip49_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / LITECOIN'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # CASH 49
        bip_obj_mst = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN_CASH)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip49_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip49_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_49 = inf.count_49 + 1
        
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip49_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip49_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN_CASH - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip49_hc_b))
                print('* hash Uncompress begin - {}'.format(bip49_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip49_hc))
                print('* hash Uncompress - {}'.format(bip49_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / BITCOIN_CASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # SV 49
        bip_obj_mst = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN_SV)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip49_hc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawCompressed().ToBytes()).hex()
        bip49_huc_b = CryptoUtils.Hash160(bip_obj_chain.PublicKey().RawUncompressed().ToBytes()).hex()
        inf.count_49 = inf.count_49 + 1
        
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)
            bip49_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
            bip49_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug > 0:
                print('* cyrency - {}'.format("BITCOIN_SV - " + str(nom)))
                print('* Debug Mnemonic : '+ mnemonic)
                print('* Public RawCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed begin - {}'.format(bip_obj_chain.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress begin - {}'.format(bip49_hc_b))
                print('* hash Uncompress begin - {}'.format(bip49_huc_b))
                print('* address Compress - {}'.format(bip_obj_chain.PublicKey().ToAddress()))
                print('* Public RawCompressed - {}'.format(bip_obj_addr.PublicKey().RawCompressed().ToHex()))
                print('* Public RawUnCompressed - {}'.format(bip_obj_addr.PublicKey().RawUncompressed().ToHex()))
                print('* hash Compress - {}'.format(bip49_hc))
                print('* hash Uncompress - {}'.format(bip49_huc))
                print('* address Compress - {}'.format(bip_obj_addr.PublicKey().ToAddress()))
                print('-'*60)
            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / BITCOIN_SV'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

def run32(bf_32,mode,words,debug,process_count_work,list30):
    try:
        ind:int = 1
        while ind > 0:
            start_time = time.time()
            work32(bf_32,mode,words,debug,list30)
            inf.process_time_work = time.time() - start_time
            if process_count_work == 1:
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total key: {:d} | key/s: {:d} | Found {:d}'.format(ind, inf.count_32*(ind), int(inf.count_32/inf.process_time_work), inf.key_found),end='\r')

            if process_count_work > 1:
            	if multiprocessing.current_process().name == 'CPU/0':
            	    print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, inf.count_32*ind*process_count_work,int((inf.count_32/inf.process_time_work)*process_count_work),inf.key_found),flush=True,end='\r')
            ind +=1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()


def run44(bf_44,mode,words,debug,process_count_work,list30):
    try:
        ind:int = 1
        while ind > 0:
            start_time = time.time()
            work44(bf_44,mode,words,debug,list30)
            inf.process_time_work = time.time() - start_time
            if process_count_work == 1:
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total key: {:d} | key/s: {:d} | Found {:d}'.format(ind, inf.count_44*(ind), int(inf.count_44/inf.process_time_work), inf.key_found),end='\r')
            if process_count_work > 1:
            	if multiprocessing.current_process().name == 'CPU/0':
            	    print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, inf.count_44*ind*process_count_work,int((inf.count_44/inf.process_time_work)*process_count_work),inf.key_found),flush=True,end='\r')
            ind +=1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()

def run49(bf_49,mode,words,debug,process_count_work):
    try:
        ind:int = 1
        while ind > 0:
            start_time = time.time()
            work49(bf_49,mode,words,debug)
            inf.process_time_work = time.time() - start_time
            if process_count_work == 1:
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total key: {:d} | key/s: {:d} | Found {:d}'.format(ind, inf.count_49*(ind), int(inf.count_49/inf.process_time_work), inf.key_found),end='\r')
            if process_count_work > 1:
            	if multiprocessing.current_process().name == 'CPU/0':
            	    print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, inf.count_49*ind*process_count_work,int((inf.count_49/inf.process_time_work)*process_count_work),inf.key_found),flush=True,end='\r')
            ind +=1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    inf.type_bip, inf.dir_bf, inf.process_count_work, inf.mode, email.des_mail, inf.words, inf.debug  = createParser()
    print('-'*60,end='\n')
    print('* Version: {} '.format(inf.version))

    if inf.words == 12:
        inf.words = 128
    else:
        inf.words =256

    if inf.mode in ('s', 'r'):
        if (inf.mode == 's'):
            inf.mode_text = 'Standart'
        elif (inf.mode == 'r'):
            inf.mode_text = 'Random'
    else:
        print('Wrong mode selected')
        sys.exit()

    if inf.debug > 0 and inf.mode == 'r':
        print('random mode is not compatible with debug')
        sys.exit()

    if inf.process_count_work < 1:
        print('The number of processes must be greater than 0')
        sys.exit()
    if inf.process_count_work > multiprocessing.cpu_count():
        print('The specified number of processes exceeds the allowed')
        print('FIXED for the allowed number of processesв')
        inf.process_count_work = multiprocessing.cpu_count()

    print('* Total kernel of CPU: {} '.format(multiprocessing.cpu_count()))
    print('* Used kernel: {} '.format(inf.process_count_work))
    print('* Mode Search: BIP-{} {} '.format (inf.type_bip,inf.mode_text))
    print('* Dir database Bloom Filter: {} '.format (inf.dir_bf))
    print('* Languages at work: {} '.format(inf.mnemonic_lang))
#--------------------------------------------------
    if inf.type_bip == 32:
        print('---------------Load BF---------------')
        bf = load_BF('32.bf')
        btc30 = load_btc30('btc30.h160')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run32, name= 'CPU/'+str(index), args = (bf, inf.mode, inf.words, inf.debug, inf.process_count_work,btc30,))
                proc.start()
                procs.append(proc)
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        try:
            for proc in procs:
                proc.join()
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
#--------------------------------------------------
    if inf.type_bip == 44:
        print('---------------Load BF---------------')
        bf = load_BF(bf_file='44.bf')
        btc30 = load_btc30('btc30.h160')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run44, name= 'CPU/'+str(index), args = (bf, inf.mode, inf.words, inf.debug, inf.process_count_work,btc30, ))
                proc.start()
                procs.append(proc)
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        try:
            for proc in procs:
                proc.join()
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
#--------------------------------------------------
    if inf.type_bip == 49:
        print('---------------Load BF---------------')
        bf = load_BF('49.bf')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run49, name= 'CPU/'+str(index), args = (bf, inf.mode, inf.words, inf.debug, inf.process_count_work, ))
                proc.start()
                procs.append(proc)
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        try:
            for proc in procs:
                proc.join()
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()