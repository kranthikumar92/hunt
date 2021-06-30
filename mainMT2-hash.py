from multiprocessing import Process, current_process
import multiprocessing
import secrets
import smtplib
from bip_utils import  Bip44, Bip44Coins, Bip44Changes, Bip49, Bip32#Bip32Secp256k1
from bip_utils.utils import CryptoUtils
from bloomfilter import BloomFilter
from mnemonic import Mnemonic
import sys
import time
from colorama import init, Fore, Back, Style
import argparse
init()


class email:
    host:str = 'smtp.timeweb.ru'
    port:int = 25
    password:str = '111111111111111'
    subject:str = '--- Find Mnemonic ---'
    to_addr:str = 'info@quadrotech.ru'
    from_addr:str = 'info@quadrotech.ru'
    des_mail = ''


class inf:
    version:str = ' Pulsar v3.5.0 multiT Hash160'
    mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese']
    #mnemonic_lang = ['english', 'chinese_simplified', 'french', 'spanish','japanese']
    #mnemonic_lang = ['english']
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
    debug_:bool = False


def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=int, help='32, 44, 49 default bip32', default='32')
    parser.add_argument ('-d', '--dir_bf', action='store', type=str, help='directories to BF', default='BF')
    parser.add_argument ('-t', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode', default='s')
    parser.add_argument ('-c', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-w', '--words', action='store', type=int, help='words 12, 24', default=12)
    parser.add_argument ('-e', '--debug', action='store_true', help='debug')
    return parser.parse_args().bip, parser.parse_args().dir_bf, parser.parse_args().threading, parser.parse_args().mode, parser.parse_args().desc, parser.parse_args().words, parser.parse_args().debug


def load_BF(bf_file):
    global bf_32
    global bf_44
    global bf_49
    try:
        fp = open(inf.dir_bf+'/'+bf_file, 'rb')
    except FileNotFoundError:
        print('\n'+'File: '+ bf_file + ' not found.')
        sys.exit()
    else:
        if bf_file == '32.bf':
            bf_32 = BloomFilter.load(fp)
        if bf_file == '44.bf':
            bf_44 = BloomFilter.load(fp)
        if bf_file == '49.bf':
            bf_49 = BloomFilter.load(fp)
        print('Bloom Filter '+bf_file+' Loaded')


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


def work32(bf_32,mode,words,debug):
    inf.count_32 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
                seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        bip32_ctx = Bip32.FromSeed(seed_bytes)#Bip32Secp256k1.FromSeed(seed_bytes)
    #-----------------------------------------------------------------------------------------------------------------
        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/" + str(num))  # m/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/0/" + str(num))  # m/0'/0/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/0/" + str(num)+"'")  # m/0'/0/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/" + str(num)+"'")  # m/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/0'/" + str(num))  # m/0'/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0'/0'/" + str(num)+"'")  # m/0'/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("44'/0'/0'/" + str(num))  # m/44'/0'/0'/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("44'/0'/0'/" + str(num)+"'")  # m/44'/0'/0'/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("0/" + str(num))  # m/0/0
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        for num in range(20):
            inf.count_32 = inf.count_32 + 2
            bip32_ctx_ex = bip32_ctx.DerivePath("44'/0'/0'/0/" + str(num))  # m/0/0'
            bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx_ex.PublicKey().RawUncompressed().ToBytes()).hex()
            if debug:
                print('Public RawCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip32_ctx_ex.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip32_h160_1))
                print('hash Uncompress - {}'.format(bip32_h160_2))
            if (bip32_h160_1 in bf_32) or (bip32_h160_2 in bf_32):
                print('============== Find =================')
                bip32_PK = bip32_ctx_ex.PrivateKey().ToWif()
                #bip32_PK_raw = bip32_ctx_ex.PrivateKey().Raw().ToHex()
                res = bip32_h160_1 + ' | '+ bip32_h160_2 + ' | TRUE | ' + mnemonic + ' | ' + bip32_PK +' | BIP 32 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)


def work44(bf_44,mode,words,debug):
    inf.count_44 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
                seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        # btc
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)

        bip44_pc_b = bip_obj_chain.PublicKey().RawCompressed().ToBytes()
        bip44_pc_b = bip_obj_chain.PublicKey().RawUncompressed().ToBytes()
        bip44_hc_b = CryptoUtils.Hash160(bip44_pc_b)
        bip44_huc_b = CryptoUtils.Hash160(bip44_pc_b)

        inf.count_44 = inf.count_44 + 1
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)

            bip44_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip44_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip44_hc = CryptoUtils.Hash160(bip44_pc)
            bip44_huc = CryptoUtils.Hash160(bip44_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip44_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip44_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip44_hc))
                print('hash Uncompress - {}'.format(bip44_huc))
            if (bip44_hc_b in bf_44) or (bip44_huc_b in bf_44) or (bip44_hc in bf_44) or (bip44_huc in bf_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip44_hc_b+' | '+bip44_huc_b+' | '+bip44_hc+' | '+bip44_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip44_PK +' | BIP 44 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # btc_cash
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_CASH)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_pc_b = bip_obj_chain.PublicKey().RawCompressed().ToBytes()
        bip44_pc_b = bip_obj_chain.PublicKey().RawUncompressed().ToBytes()
        bip44_hc_b = CryptoUtils.Hash160(bip44_pc_b)
        bip44_huc_b = CryptoUtils.Hash160(bip44_pc_b)

        inf.count_44 = inf.count_44 + 1
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)

            bip44_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip44_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip44_hc = CryptoUtils.Hash160(bip44_pc)
            bip44_huc = CryptoUtils.Hash160(bip44_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip44_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip44_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip44_hc))
                print('hash Uncompress - {}'.format(bip44_huc))
            if (bip44_hc_b in bf_44) or (bip44_huc_b in bf_44) or (bip44_hc in bf_44) or (bip44_huc in bf_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip44_hc_b+' | '+bip44_huc_b+' | '+bip44_hc+' | '+bip44_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip44_PK +' | BIP 44 / CASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # ltc
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.LITECOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_pc_b = bip_obj_chain.PublicKey().RawCompressed().ToBytes()
        bip44_pc_b = bip_obj_chain.PublicKey().RawUncompressed().ToBytes()
        bip44_hc_b = CryptoUtils.Hash160(bip44_pc_b)
        bip44_huc_b = CryptoUtils.Hash160(bip44_pc_b)

        inf.count_44 = inf.count_44 + 1
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)

            bip44_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip44_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip44_hc = CryptoUtils.Hash160(bip44_pc)
            bip44_huc = CryptoUtils.Hash160(bip44_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip44_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip44_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip44_hc))
                print('hash Uncompress - {}'.format(bip44_huc))
            if (bip44_hc_b in bf_44) or (bip44_huc_b in bf_44) or (bip44_hc in bf_44) or (bip44_huc in bf_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip44_hc_b+' | '+bip44_huc_b+' | '+bip44_hc+' | '+bip44_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip44_PK +' | BIP 44 / DASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # DOGE
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.DOGECOIN)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_pc_b = bip_obj_chain.PublicKey().RawCompressed().ToBytes()
        bip44_pc_b = bip_obj_chain.PublicKey().RawUncompressed().ToBytes()
        bip44_hc_b = CryptoUtils.Hash160(bip44_pc_b)
        bip44_huc_b = CryptoUtils.Hash160(bip44_pc_b)

        inf.count_44 = inf.count_44 + 1
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)

            bip44_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip44_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip44_hc = CryptoUtils.Hash160(bip44_pc)
            bip44_huc = CryptoUtils.Hash160(bip44_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip44_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip44_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip44_hc))
                print('hash Uncompress - {}'.format(bip44_huc))
            if (bip44_hc_b in bf_44) or (bip44_huc_b in bf_44) or (bip44_hc in bf_44) or (bip44_huc in bf_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip44_hc_b+' | '+bip44_huc_b+' | '+bip44_hc+' | '+bip44_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip44_PK +' | BIP 44 / DOGE'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
        # sv
        bip_obj_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN_SV)
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(0)
        bip_obj_chain = bip_obj_acc.Change(Bip44Changes.CHAIN_EXT)
        bip44_pc_b = bip_obj_chain.PublicKey().RawCompressed().ToBytes()
        bip44_pc_b = bip_obj_chain.PublicKey().RawUncompressed().ToBytes()
        bip44_hc_b = CryptoUtils.Hash160(bip44_pc_b)
        bip44_huc_b = CryptoUtils.Hash160(bip44_pc_b)

        inf.count_44 = inf.count_44 + 1
        for nom in range(20):
            inf.count_44 = inf.count_44 + 2
            bip_obj_addr = bip_obj_chain.AddressIndex(nom)

            bip44_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip44_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip44_hc = CryptoUtils.Hash160(bip44_pc)
            bip44_huc = CryptoUtils.Hash160(bip44_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip44_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip44_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip44_hc))
                print('hash Uncompress - {}'.format(bip44_huc))
            if (bip44_hc_b in bf_44) or (bip44_huc_b in bf_44) or (bip44_hc in bf_44) or (bip44_huc in bf_44):
                print('============== Find =================')
                bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip44_hc_b+' | '+bip44_huc_b+' | '+bip44_hc+' | '+bip44_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip44_PK +' | BIP 44 / DOGE'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)
                


def work49(bf_49,mode,words,debug):
    inf.count_49 = 0
    for mem in inf.mnemonic_lang:
        if mode == 'r':
            seed_bytes:bytes = secrets.token_bytes(64)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
                seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        else:
            mnemo = Mnemonic(mem)
            mnemonic:str = mnemo.generate(words)
            if debug:
                mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
                print('Debug Mnemonic : '+mnemonic)
            seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')

        # btc 49
        master_key = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN) # mainnet
        bip49_account = master_key.Purpose().Coin().Account(0)
        bip49_change = bip49_account.Change(Bip44Changes.CHAIN_EXT)
        bip49_pc_b = bip49_change.PublicKey().RawCompressed().ToBytes()
        bip49_pc_b = bip49_change.PublicKey().RawUncompressed().ToBytes()
        bip49_hc_b = CryptoUtils.Hash160(bip49_pc_b)
        bip49_huc_b = CryptoUtils.Hash160(bip49_pc_b)
        inf.count_49 = inf.count_49 + 1
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip49_change.AddressIndex(nom)

            bip49_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip49_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip49_hc = CryptoUtils.Hash160(bip49_pc)
            bip49_huc = CryptoUtils.Hash160(bip49_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip49_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip49_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip49_hc))
                print('hash Uncompress - {}'.format(bip49_huc))

            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / BTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # ltc 49
        master_key = Bip49.FromSeed(seed_bytes, Bip44Coins.LITECOIN) # mainnet
        bip49_account = master_key.Purpose().Coin().Account(0)
        bip49_change = bip49_account.Change(Bip44Changes.CHAIN_EXT)
        bip49_pc_b = bip49_change.PublicKey().RawCompressed().ToBytes()
        bip49_pc_b = bip49_change.PublicKey().RawUncompressed().ToBytes()
        bip49_hc_b = CryptoUtils.Hash160(bip49_pc_b)
        bip49_huc_b = CryptoUtils.Hash160(bip49_pc_b)
        inf.count_49 = inf.count_49 + 1
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip49_change.AddressIndex(nom)

            bip49_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip49_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip49_hc = CryptoUtils.Hash160(bip49_pc)
            bip49_huc = CryptoUtils.Hash160(bip49_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip49_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip49_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip49_hc))
                print('hash Uncompress - {}'.format(bip49_huc))

            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / LTC'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # CASH 49
        master_key = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN_CASH) # mainnet
        bip49_account = master_key.Purpose().Coin().Account(0)
        bip49_change = bip49_account.Change(Bip44Changes.CHAIN_EXT)
        bip49_pc_b = bip49_change.PublicKey().RawCompressed().ToBytes()
        bip49_pc_b = bip49_change.PublicKey().RawUncompressed().ToBytes()
        bip49_hc_b = CryptoUtils.Hash160(bip49_pc_b)
        bip49_huc_b = CryptoUtils.Hash160(bip49_pc_b)
        inf.count_49 = inf.count_49 + 1
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip49_change.AddressIndex(nom)

            bip49_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip49_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip49_hc = CryptoUtils.Hash160(bip49_pc)
            bip49_huc = CryptoUtils.Hash160(bip49_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip49_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip49_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip49_hc))
                print('hash Uncompress - {}'.format(bip49_huc))

            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / CASH'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

        # SV 49
        master_key = Bip49.FromSeed(seed_bytes, Bip44Coins.BITCOIN_SV) # mainnet
        bip49_account = master_key.Purpose().Coin().Account(0)
        bip49_change = bip49_account.Change(Bip44Changes.CHAIN_EXT)
        bip49_pc_b = bip49_change.PublicKey().RawCompressed().ToBytes()
        bip49_pc_b = bip49_change.PublicKey().RawUncompressed().ToBytes()
        bip49_hc_b = CryptoUtils.Hash160(bip49_pc_b)
        bip49_huc_b = CryptoUtils.Hash160(bip49_pc_b)
        inf.count_49 = inf.count_49 + 1
        for nom in range(20):
            inf.count_49 = inf.count_49 + 2
            bip_obj_addr = bip49_change.AddressIndex(nom)

            bip49_pc = bip_obj_addr.PublicKey().RawCompressed().ToBytes()
            bip49_puc = bip_obj_addr.PublicKey().RawUncompressed().ToBytes()

            bip49_hc = CryptoUtils.Hash160(bip49_pc)
            bip49_huc = CryptoUtils.Hash160(bip49_puc)
            if debug:
                print('Public RawCompressed - {}'.format(bip49_pc.PublicKey().RawCompressed().ToHex()))
                print('Public RawUnCompressed - {}'.format(bip49_puc.PublicKey().RawUncompressed().ToHex()))
                print('hash Compress - {}'.format(bip49_hc))
                print('hash Uncompress - {}'.format(bip49_huc))

            if (bip49_hc_b in bf_49) or (bip49_huc_b in bf_49) or (bip49_hc in bf_49) or (bip49_huc in bf_49):
                print('============== Find =================')
                bip49_PK = bip_obj_addr.PrivateKey().ToWif()
                res:str = bip49_hc_b+' | '+bip49_huc_b+' | '+bip49_hc+' | '+bip49_huc+ ' | TRUE | ' + mnemonic + ' | ' + bip49_PK +' | BIP 49 / SV'
                print(res)
                inf.key_found = inf.key_found + 1
                save_rezult(res)
                send_email(res)

def run32(bf_32,mode,words,debug,process_count_work):
    try:
        ind:int = 1
        while ind > 0:
            start_time = time.time()
            work32(bf_32,mode,words,debug)
            exit
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


def run44(bf_44,mode,words,debug,process_count_work):
    try:
        ind:int = 1
        while ind > 0:
            start_time = time.time()
            work44(bf_44,mode,words,debug)
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
        load_BF('32.bf')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run32, name= 'CPU/'+str(index), args = (bf_32, inf.mode, inf.words, inf.debug_, inf.process_count_work,))
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
        print('\n---------------Load BF---------------')
        load_BF('44.bf')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run44, name= 'CPU/'+str(index), args = (bf_44, inf.mode, inf.words, inf.debug_, inf.process_count_work, ))
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
        print('\n---------------Load BF---------------')
        load_BF('49.bf')
        print('-------------------------------------',end='\n')
        procs = []
        try:
            for index in range(inf.process_count_work):
                proc = Process(target=run49, name= 'CPU/'+str(index), args = (bf_49, inf.mode, inf.words, inf.debug_, inf.process_count_work, ))
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