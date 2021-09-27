# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-

from funcP import *
from consts import *
import time, argparse
import multiprocessing
from multiprocessing import Process
from colorama import init,Fore
import sys
init()

def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=str, help='32, 44, ETH default bip32', default='32')
    parser.add_argument ('-db', '--database', action='store', type=str, help='File BF', default='')
    parser.add_argument ('-dbp', '--database_puzzle', action='store', type=str, help='File pazzle', default='')
    parser.add_argument ('-th', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode s or r', default='s')
    parser.add_argument ('-des', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-bit', '--bit', action='store', type=int, help='32, 64, 96, 128, 160, 192, 224, 256', default=128)
    parser.add_argument ('-dbg', '--debug', action='store', type=int, help='debug 0 1 2', default=0)
    parser.add_argument ('-em', '--mail', action='store', type=str, help='send mail or not ', default='no')
    parser.add_argument ('-sc', '--sock', action='store', type=str, help='send statistic to server ', default='no')
    return parser.parse_args().bip, parser.parse_args().database, parser.parse_args().database_puzzle, parser.parse_args().threading, parser.parse_args().mode, \
        parser.parse_args().desc, parser.parse_args().bit, parser.parse_args().debug, parser.parse_args().mail, parser.parse_args().sock

def run(bip, db_bf, db_puzle, puzle, mode, desc, bit, debug, mail, sockets, th, counter):
    inf.uid = str(uuid.UUID(int=uuid.getnode())).encode('utf-8')[24:]
    inf.db_bf = db_bf
    inf.db_puzle=db_puzle
    inf.puzle = puzle
    inf.mode=mode
    email.desc=desc
    inf.bit=bit
    inf.debug=debug
    inf.mail=mail
    inf.sockets=sockets
    inf.th = th
    ind:int = 1
    soc_count = 0
    load_BF(inf.db_bf)
    if inf.puzle: load_btc30(inf.db_puzle)
    try:
        while True:
            inf.count = 0
            start_time = time.time()
            for mem in inf.mnemonic_lang:
                mnemonic, seed_bytes = nnmnem(mem)
                if bip == "32" : b32(mnemonic,seed_bytes,counter)
                if bip == "44" : b44(mnemonic,seed_bytes,counter)
                if bip == "ETH": bETH(mnemonic,seed_bytes,counter)
            st = time.time() - start_time
            speed = int((inf.count/st)*inf.th)
            total = inf.count*ind*inf.th
            mm = ind*len(inf.mnemonic_lang)*inf.th
            if multiprocessing.current_process().name == 'CPU/0':
                print('\033[1;33m > Mnemonic: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} \033[0m'.format(mm, total,speed, counter.value()),flush=True,end='\r')
                if (inf.sockets == 'yes') and (soc_count > 30):
                    send_stat(speed,total,counter.value())
                    soc_count = 0
            ind +=1
            soc_count += 1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()

if __name__ == "__main__":
    multiprocessing.freeze_support()
    inf.bip, inf.db_bf, inf.db_puzle, inf.th, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sockets  = createParser()
    inf.uid = str(uuid.UUID(int=uuid.getnode())).encode('utf-8')[24:]
    print('-'*59,end='\n')
    print('DEPENDENCY TESTING:')
    pk_uc_test = '046c2fc710d630df3031599a35e641f42221b598698d42d8995518ac9336a4d22487b4722b0f54031b3a19475feb2ea844e826f75b54bf9388e9a348acc5f5c448'
    try:
        bip_addr_uc = P2PKH.ToAddress(pk_uc_test,net_addr_ver=b"\x00")
    except:
        print('\033[1;31m ERROR: no support for converting addresses')
        print('\033[1;31m Please delete (pip uninstall bip_utils)')
        print('\033[1;34m install my mod (https://github.com/Noname400/bip-utils) \033[0m')
        sys.exit()
    try:
        mnemo:Mnemonic = Mnemonic('english')
        mnemonic:str = mnemo.generate(strength=32)
    except:
        print('\033[1;31m ERROR: generate mnemonic')
        print('\033[1;31m Please delete (pip uninstall mnemonic)')
        print('\033[1;34m install my mod (https://github.com/Noname400/python-mnemonic) \033[0m')
        sys.exit()

    if platform.system().lower().startswith('win'):
        dllfile = 'ice_secp256k1.dll'
        if os.path.isfile(dllfile) == True:
            pass
        else:
            print('\033[1;31m File {} not found \033[0m'.format(dllfile))
        
    elif platform.system().lower().startswith('lin'):
        dllfile = 'ice_secp256k1.so'
        if os.path.isfile(dllfile) == True:
            pass
        else:
            print('\033[1;31m File {} not found \033[0m'.format(dllfile))
    else:
        print('\033[1;31m * Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working \033[0m')
        sys.exit()

    print('\033[32m TEST: OK! \033[0m')

    if inf.bip in ('32', '44', 'ETH'):
        pass
    else:
        print('\033[1;31m Wrong BIP selected \033[0m')
        sys.exit()

    if inf.mail !='yes': inf.mail='no'

    if inf.sockets !='yes': inf.sockets='no'

    if (inf.db_puzle !=""): inf.puzle = True

    if inf.bip =="ETH": inf.puzle = False

    if inf.bit in (32, 64, 96, 128, 160, 192, 224, 256):
        pass          
    else:
        print('\033[1;31m Wrong words selected \033[0m')
        sys.exit()

    if inf.mode in ('s', 'r'):
        if (inf.mode == 's'):
            inf.mode_text = 'Standart'
        elif (inf.mode == 'r'):
            inf.mode_text = 'Random'
    else:
        print('\033[1;31m Wrong mode selected')
        sys.exit()

    if inf.th < 1:
        print('\033[1;31m The number of processes must be greater than 0 \033[0m')
        sys.exit()

    if inf.th > multiprocessing.cpu_count():
        print('The specified number of processes exceeds the allowed')
        print('FIXED for the allowed number of processes')
        inf.th = multiprocessing.cpu_count()

    print('-'*59,end='\n')
    print('* Version: {} '.format(inf.version))
    print('* Identificator system: {}'.format(inf.uid.decode("utf-8")))
    print('* Total kernel of CPU: {} '.format(multiprocessing.cpu_count()))
    print('* Used kernel: {} '.format(inf.th))
    print('* Mode Search: BIP-{} {} '.format (inf.bip, inf.mode_text))
    print('* Dir database Bloom Filter: {} '.format (inf.db_bf))
    if inf.puzle: print('* Dir database Pazzle: {} '.format (inf.db_puzle))
    print('* Languages at work: {} '.format(inf.mnemonic_lang))
    print('* Work BIT: {} '.format(inf.bit))
    print('* Description client: {} '.format(email.desc))

    if inf.mail == 'yes': print('* Send mail: On')
    else: print('* Send mail: Off')
    if inf.sockets == 'yes':
        print('* Send Statistic to server: On')
    else:
        print('* Send Statistic to server: Off')
    print('-'*59,end='\n')
    counter = Counter()
    procs = []

    try:
        procs = [Process(target=run, name= 'CPU/'+str(i), args=(inf.bip, inf.db_bf, inf.db_puzle,inf.puzle,inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sockets, inf.th, counter,)) for i in range(inf.th)]
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()
    try:
        for p in procs: p.start()
        for p in procs: p.join()
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()
    