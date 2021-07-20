# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-

from include.funcP import *
import sys,time,argparse,uuid #datetime, socket, 
import multiprocessing#,hashlib,codecs,secrets,smtplib
from multiprocessing import Process, Value
from bip_utils import Bip44Coins#, Bip44,  Bip44Changes, Bip49, Bip32
#from bip_utils.utils import CryptoUtils
from bloomfilter import BloomFilter
#from mnemonic import Mnemonic
from colorama import init, Fore
init()


class socket_set:
    server = 'localhost'
    port = 9009

class email:
    host:str = 'smtp.timeweb.ru'
    port:int = 25
    password:str = '-------------'
    subject:str = '--- Find Mnemonic ---'
    to_addr:str = 'info@quadrotech.ru'
    from_addr:str = 'info@quadrotech.ru'
    des_mail = ''

class inf:
    version:str = ' Pulsar v3.7.6b multiT Hash160'
    #mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french', 'italian', 'spanish', 'korean','japanese']
    #mnemonic_lang = ['english', 'chinese_simplified', 'chinese_traditional', 'french']
    mnemonic_lang = ['english']
    count:int = 0
    process_count_work:int = 0 #number of processes
    type_bip:int = 0
    dir_bf:str = ''
    process_time_work = 0.0
    mode = ''
    mode_text = ''
    key_found = 0
    words = 0
    debug:int = 0
    mail = ''
    dt_now = ''
    socket = ''
    uid:uuid
    bf:BloomFilter
    list30 = []
    l32 = ["m/0/","m/0'/","m/0'/0/","m/0'/0'/","m/44'/0'/0'/"]
    l32_ = ["","'"]
    lBTC = [Bip44Coins.BITCOIN,Bip44Coins.BITCOIN_CASH,Bip44Coins.BITCOIN_SV]
    l44 = [Bip44Coins.BITCOIN,Bip44Coins.BITCOIN_CASH,Bip44Coins.LITECOIN,Bip44Coins.DASH,Bip44Coins.DOGECOIN,Bip44Coins.BITCOIN_SV]
    l44_ = [b'00',b'00',b'30',b'4C',b'1E',b'00']
    l44__ = [Bip44Changes.CHAIN_EXT,Bip44Changes.CHAIN_INT]


def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=str, help='32, 44, 49 ETH BTC default bip32', default='32')
    parser.add_argument ('-d', '--dir_bf', action='store', type=str, help='directories to BF', default='BF')
    parser.add_argument ('-t', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode', default='s')
    parser.add_argument ('-c', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-w', '--words', action='store', type=int, help='words 12, 24', default=12)
    parser.add_argument ('-e', '--debug', action='store', type=int, help='debug 0 1 2', default=0)
    parser.add_argument ('-em', '--mail', action='store', type=str, help='send mail or not ', default='yes')
    parser.add_argument ('-s', '--stat', action='store', type=str, help='send statistic to server ', default='yes')
    return parser.parse_args().bip, parser.parse_args().dir_bf, parser.parse_args().threading, parser.parse_args().mode, parser.parse_args().desc, parser.parse_args().words, parser.parse_args().debug, parser.parse_args().mail, parser.parse_args().stat


def runETH(bip,mode,words,debug,process_count_work,mail,des,uid,sock,counter,dir_bf):
    inf.uid = uid
    inf.mode = mode
    inf.words = words
    inf.debug = debug
    inf.process_count_work = process_count_work
    inf.socket = sock
    inf.mail = mail
    inf.dir_bf = dir_bf
    email.des_mail = des
    inf.type_bip = bip
    inf.count = 1
    soc_count = 0
    ind:int = 1
    inf.bf = load_BF(inf.dir_bf,'eth.bf')
    try:
        while ind > 0:
            inf.count = 0
            start_time = time.time()
            for mem in inf.mnemonic_lang:
                mnemonic, seed_bytes = nnmnem(inf, mem)
                bETH(inf, email, mnemonic,seed_bytes,counter)
            inf.process_time_work = time.time() - start_time
            speed = int((inf.count/inf.process_time_work)*inf.process_count_work)
            total = inf.count*ind*inf.process_count_work
            if multiprocessing.current_process().name == 'CPU/0':
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, total,speed, counter.value()),flush=True,end='\r')
                if (inf.socket == 'yes') and (soc_count > 30):
                    send_stat(socket_set, inf,inf.uid,email.des_mail,inf.type_bip,inf.process_count_work,speed,total,counter.value())
                    soc_count = 0
            ind +=1
            soc_count += 1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()


def run32(bip,mode,words,debug,process_count_work,mail,des,uid,sock,counter,dir_bf):
    inf.uid = uid
    inf.mode = mode
    inf.words = words
    inf.debug = debug
    inf.process_count_work = process_count_work
    inf.socket = sock
    inf.mail = mail
    inf.dir_bf = dir_bf
    email.des_mail = des
    inf.type_bip = bip
    inf.count = 1
    soc_count = 0
    ind:int = 1
    inf.bf = load_BF(inf.dir_bf,'32.bf')
    inf.list30 = load_btc30(inf.dir_bf,'btc30.h160')
    try:
        while ind > 0:
            inf.count = 0
            start_time = time.time()
            for mem in inf.mnemonic_lang:
                mnemonic, seed_bytes = nnmnem(inf, mem)
                b32(inf, email, mnemonic,seed_bytes,counter)
            inf.process_time_work = time.time() - start_time
            speed = int((inf.count/inf.process_time_work)*inf.process_count_work)
            total = inf.count*ind*inf.process_count_work
            if multiprocessing.current_process().name == 'CPU/0':
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, total,speed, counter.value()),flush=True,end='\r')
                if (inf.socket == 'yes') and (soc_count > 20):
                    send_stat(socket_set, inf,inf.uid,email.des_mail,inf.type_bip,inf.process_count_work,speed,total,counter.value())
                    soc_count = 0
            ind +=1
            soc_count += 1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()


def run44(bip,mode,words,debug,process_count_work,mail,des,uid,sock,counter,dir_bf):
    inf.uid = uid
    inf.mode = mode
    inf.words = words
    inf.debug = debug
    inf.process_count_work = process_count_work
    inf.socket = sock
    inf.mail = mail
    inf.dir_bf = dir_bf
    email.des_mail = des
    inf.type_bip = bip
    inf.count = 1
    soc_count = 0
    ind:int = 1
    inf.bf = load_BF(inf.dir_bf,'44.bf')
    inf.list30 = load_btc30(inf.dir_bf,'btc30.h160')
    try:
        while ind > 0:
            inf.count = 0
            start_time = time.time()
            for mem in inf.mnemonic_lang:
                mnemonic, seed_bytes = nnmnem(inf, mem)
                b44(inf, email, mnemonic,seed_bytes,counter)
            inf.process_time_work = time.time() - start_time
            speed = int((inf.count/inf.process_time_work)*inf.process_count_work)
            total = inf.count*ind*inf.process_count_work
            if multiprocessing.current_process().name == 'CPU/0':
                print(Fore.YELLOW+'[*] Cycle: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} '.format(ind, total,speed, counter.value()),flush=True,end='\r')
                if (inf.socket == 'yes') and (soc_count > 30):
                    send_stat(socket_set,inf, inf.uid,email.des_mail,inf.type_bip,inf.process_count_work,speed,total,counter.value())
                    soc_count = 0
            ind +=1
            soc_count += 1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    type_bip, dir_bf, process_count_work, mode, des_mail, words, debug, mail, socket_  = createParser()
    uid = str(uuid.UUID(int=uuid.getnode())).encode('utf-8')#[24:]
    #uid = secrets.token_hex(8).encode('utf-8')
    if mail !='yes':
        mail='no'
    if socket_ !='yes':
        socket_='no'
    if words == 12:
        words = 128
    else:
        words =256
    if mode in ('s', 'r'):
        if (mode == 's'):
            mode_text = 'Standart'
        elif (mode == 'r'):
            mode_text = 'Random'
    else:
        print('Wrong mode selected')
        sys.exit()
    if debug > 0 and mode == 'r':
        print('random mode is not compatible with debug')
        sys.exit()
    if process_count_work < 1:
        print('The number of processes must be greater than 0')
        sys.exit()
    if process_count_work > multiprocessing.cpu_count():
        print('The specified number of processes exceeds the allowed')
        print('FIXED for the allowed number of processesв')
        process_count_work = multiprocessing.cpu_count()
    print('-'*59,end='\n')
    print('* Version: {} '.format(inf.version))
    print('* Identificator system: {}'.format(uid))
    print('* Total kernel of CPU: {} '.format(multiprocessing.cpu_count()))
    print('* Used kernel: {} '.format(process_count_work))
    print('* Mode Search: BIP-{} {} '.format (type_bip,mode_text))
    print('* Dir database Bloom Filter: {} '.format (dir_bf))
    print('* Languages at work: {} '.format(inf.mnemonic_lang))
    print('* Description Server: {} '.format(des_mail))
    if debug > 0:
        print('* Mode debug: On')
    else:
        print('* Mode debug: Off')
    if mail == 'yes':
        print('* Send mail: On')
    else:
        print('* Send mail: Off')
    if socket_ == 'yes':
        print('* Send Statistic to server: On')
    else:
        print('* Send Statistic to server: Off')
    counter = Counter(0)
    #--------------------------------------------------
    if type_bip == '32':
        try:
            procs = [Process(target=run32, name= 'CPU/'+str(i), args=(type_bip, mode, words, 
                    debug, process_count_work,mail,des_mail,uid,socket_,counter,dir_bf,)) for i in range(process_count_work)]
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        else:
            try:
                for p in procs: p.start()
                for p in procs: p.join()
            except KeyboardInterrupt:
                print('\n'+'Interrupted by the user.')
                sys.exit()
    #--------------------------------------------------
    if type_bip == '44':
        try:
            procs = [Process(target=run44, name= 'CPU/'+str(i), args=(type_bip, mode, words, 
                    debug, process_count_work,mail,des_mail,uid,socket_,counter,dir_bf,)) for i in range(process_count_work)]
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        try:
            for p in procs: p.start()
            for p in procs: p.join()
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
    #--------------------------------------------------
    if type_bip == 'ETH':
        try:
            procs = [Process(target=runETH, name= 'CPU/'+str(i), args=(type_bip, mode, words, 
                    debug, process_count_work,mail,des_mail,uid,socket_,counter,dir_bf,)) for i in range(process_count_work)]
        except KeyboardInterrupt:
            print('\n'+'Interrupted by the user.')
            sys.exit()
        else:
            try:
                for p in procs: p.start()
                for p in procs: p.join()
            except KeyboardInterrupt:
                print('\n'+'Interrupted by the user.')
                sys.exit()
