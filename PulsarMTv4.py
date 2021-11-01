# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
"""
@author: Noname400
"""

from funcP import *
from consts import *

def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=str, help='32/44/ETH/BTC default BIP32', default='32')
    parser.add_argument ('-db', '--database', action='store', type=str, help='File BF', default='')
    parser.add_argument ('-th', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode s/r1/r2/game/custom', default='s')
    parser.add_argument ('-des', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-bit', '--bit', action='store', type=int, help='32, 64, 96, 128, 160, 192, 224, 256', default=128)
    parser.add_argument ('-dbg', '--debug', action='store', type=int, help='debug 0/1/2', default=0)
    parser.add_argument ('-em', '--mail', action='store_true', help='send mail')
    parser.add_argument ('-sl', '--sleep', action='store', type=int, help='pause start (sec)', default='3')
    parser.add_argument ('-bal', '--balance', action='store_true', help='check balance')
    parser.add_argument ('-cd', '--customdir', action='store', type=str, help='custom dir for mode custom', default='')
    parser.add_argument ('-cw', '--customword', action='store', type=int, help='custom words for mode custom', default='6')
    parser.add_argument ('-cl', '--customlang', action='store', type=str, help='custom lang for mode custom', default='english')

    return parser.parse_args().bip, parser.parse_args().database, parser.parse_args().threading, parser.parse_args().mode, \
        parser.parse_args().desc, parser.parse_args().bit, parser.parse_args().debug, parser.parse_args().mail, parser.parse_args().sleep, parser.parse_args().balance, \
        parser.parse_args().customdir, parser.parse_args().customword, parser.parse_args().customlang

def run(bip, db_bf, mode, desc, bit, debug, mail, th, sleep, balance, cdir, cwords, clang, counter, tr):
    inf.bip = bip
    inf.db_bf = db_bf
    inf.mode = mode
    email.desc = desc
    inf.bit = bit
    inf.debug = debug
    inf.mail = mail
    inf.th = th
    inf.sleep = sleep
    inf.balance = balance
    inf.custom_dir = cdir
    inf.custom_words = cwords
    inf.custom_lang = clang
    ind:int = 1
    if inf.mode == 'r2': inf.r2_list = inf.load_r2()
    if inf.mode == 'game': inf.game_list = inf.load_game()
    if inf.mode == 'custom': inf.custom_list = inf.load_custom(inf.custom_dir)
    load_BF(inf.db_bf, tr)
    try:
        while True:
            inf.count = 0
            start_time = time.time()
            for mem in inf.mnemonic_lang:
                mnemonic, seed_bytes = nnmnem(mem)
                if inf.bip == "32" : b32(mnemonic,seed_bytes,counter)
                if inf.bip == "44" : b44(mnemonic,seed_bytes,counter)
                if inf.bip == "ETH": bETH(mnemonic,seed_bytes,counter)
                if inf.bip == "BTC": 
                    bBTC(mnemonic,seed_bytes,counter)
                    b32(mnemonic,seed_bytes,counter)
            st = time.time() - start_time
            speed = int((inf.count/st)*tr.value())
            total = inf.count*ind*tr.value()
            mm = ind*len(inf.mnemonic_lang)*tr.value()
            if multiprocessing.current_process().name == '0':
                print('\033[1;33m> Mnemonic: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} \033[0m'.format(mm, total,speed, counter.value()),flush=True,end='\r')
            ind +=1
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        sys.exit()

if __name__ == "__main__":
    inf.bip, inf.db_bf, inf.th, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sleep, inf.balance, inf.custom_dir, inf.custom_words, inf.custom_lang  = createParser()
    print('-'*70,end='\n')
    print(Fore.GREEN+Style.BRIGHT+'Thank you very much: @iceland2k14 for his libraries!\033[0m')

    if test():
        print('\033[32m[I] TEST: OK! \033[0m')
    else:
        print('\033[32m[E] TEST: ERROR \033[0m')

    if inf.bip in ('32', '44', 'ETH', 'BTC'):
        pass
    else:
        print('\033[1;31m[E] Wrong BIP selected \033[0m')
        sys.exit()

    if inf.bit in (32, 64, 96, 128, 160, 192, 224, 256):
        pass          
    else:
        print('\033[1;31m[E] Wrong words selected \033[0m')
        sys.exit()

    if inf.mode in ('s', 'r1', 'r2', 'game', 'custom'):
        if (inf.mode == 's'):
            inf.mode_text = 'Standart'
        elif (inf.mode == 'r1'):
            inf.mode_text = 'Random SEED R1'
        elif (inf.mode == 'r2'):
            inf.mode_text = 'Random Mnemonic R2'
        elif (inf.mode == 'game'):
            inf.mode_text = 'Game words'
        elif (inf.mode == 'custom'):
            if inf.custom_dir == '':
                print('[E] NOT custom file')
                sys.exit()
            inf.mode_text = 'Custom words'
    else:
        print('\033[1;31m[E] Wrong mode selected')
        sys.exit()

    if inf.th < 1:
        print('\033[1;31m[E] The number of processes must be greater than 0 \033[0m')
        sys.exit()

    if inf.th > multiprocessing.cpu_count():
        print('\033[1;31m[I] The specified number of processes exceeds the allowed\033[0m')
        print('\033[1;31m[I] FIXED for the allowed number of processes\033[0m')
        inf.th = multiprocessing.cpu_count()

    print('-'*70,end='\n')
    print(f'[I] Version: {inf.version}')
    print(f'[I] Total kernel of CPU: {multiprocessing.cpu_count()}')
    print(f'[I] Used kernel: {inf.th}')
    print(f'[I] Mode Search: BIP-{inf.bip} {inf.mode_text}')
    print(f'[I] Database Bloom Filter: {inf.db_bf}')
    if inf.custom_dir != '': print(f'[I] Сustom dictionary: {inf.custom_dir}')
    if inf.custom_dir != '': print(f'[I] Сustom words: {inf.custom_words}')
    if inf.custom_dir != '': print(f'[I] Languages at work: {inf.custom_lang}')
    if inf.mode == 's': print(f'[I] Languages at work: {inf.mnemonic_lang}')
    print(f'[I] Work BIT: {inf.bit}')
    print(f'[I] Description client: {email.desc}')
    print(f'[I] Smooth start {inf.sleep} sec')

    if inf.mail: print('[I] Send mail: On')
    else: print('[I] Send mail: Off')
    if inf.balance: print('[I] Check balance BTC: On')
    else: print('[I] Check balance: Off')
    print('-'*70,end='\n')
    counter = Counter(0)
    tr = Counter(0)

    try:
        procs = [Process(target=run, name= str(i), args=(inf.bip, inf.db_bf, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.th, 
                                                         inf.sleep, inf.balance, inf.custom_dir, inf.custom_words, inf.custom_lang, counter, tr,)) for i in range(inf.th)]
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        sys.exit()
    try:
        for p in procs: p.start()
        for p in procs: p.join()
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        sys.exit()
    