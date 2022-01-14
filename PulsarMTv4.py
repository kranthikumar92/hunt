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
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode s/e/g/c', default='s')
    parser.add_argument ('-des', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-bit', '--bit', action='store', type=int, help='128, 160, 192, 224, 256', default=128)
    parser.add_argument ('-dbg', '--debug', action='store', type=int, help='debug 0/1/2', default=0)
    parser.add_argument ('-em', '--mail', action='store_true', help='send mail')
    parser.add_argument ('-sl', '--sleep', action='store', type=int, help='pause start (sec)', default='5')
    parser.add_argument ('-bal', '--balance', action='store_true', help='check balance')
    parser.add_argument ('-brain', '--brain', action='store_true', help='check balance')
    parser.add_argument ('-cd', '--customdir', action='store', type=str, help='custom dir for mode custom', default='')
    parser.add_argument ('-cw', '--customword', action='store', type=int, help='custom words for mode custom', default='6')
    parser.add_argument ('-cl', '--customlang', action='store', type=str, help='custom lang for mode custom', default='english')
    return parser.parse_args().bip, parser.parse_args().database, parser.parse_args().threading, parser.parse_args().mode, \
        parser.parse_args().desc, parser.parse_args().bit, parser.parse_args().debug, parser.parse_args().mail, parser.parse_args().sleep, parser.parse_args().balance, \
        parser.parse_args().brain, parser.parse_args().customdir, parser.parse_args().customword, parser.parse_args().customlang

def run(bip, db_bf, mode, desc, bit, debug, mail, th, sleep, balance, mbrain, cdir, cwords, clang, count_nem, count, counter, tr, brain):
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
    inf.brain = mbrain
    inf.custom_dir = cdir
    inf.custom_words = cwords
    inf.custom_lang = clang
    total = 0
    t = 0
    tt = 0
    ind:int = 1
    if inf.bip == 'BTC' or inf.bip == '32' or inf.bip == '44': mnemonic_lang = inf.mnemonic_BTC
    else: mnemonic_lang = inf.mnemonic_ETH
    if inf.mode == 'g': inf.game_list = inf.load_game()
    if inf.game_list == None: sys.exit()
    if inf.mode == 'c': inf.custom_list = inf.load_custom(inf.custom_dir)
    if inf.custom_list == None: sys.exit()
    load_BF(inf.db_bf, tr)
    try:
        while True:
            start_time = time.time()
            for mem in mnemonic_lang:
                count_nem.increment()
                mnemonic, seed_bytes = nnmnem(mem)
                if inf.brain:
                    bw(mnemonic,brain,counter)
                    bw(seed_bytes.hex(),brain,counter)
                if inf.bip == "32" : b32(mnemonic,seed_bytes,counter,count)
                if inf.bip == "44" : b44(mnemonic,seed_bytes,counter,count)
                if inf.bip == "ETH": bETH(mnemonic,seed_bytes,counter,count)
                if inf.bip == "BTC": 
                    bBTC(mnemonic,seed_bytes,counter,count)
                    b32(mnemonic,seed_bytes,counter,count)
            st = time.time() - start_time
            t = total
            total = count.value()
            tt = total - t
            speed = int((tt/st))
            mm = count_nem.value()
            counter_ = counter.value()
            brain_ = brain.value()
            
            if multiprocessing.current_process().name == '0':
                print(f'\033[1;33m> Mnemonic: {mm} | Total keys NEM: {total} | Total keys BRAIN: {brain_} | Speed {speed} key/s | Found {counter_} \033[0m',end='\r')
            inf.count = 0
            ind +=1
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        logger_info.info('[EXIT] Interrupted by the user.')
        sys.exit()

if __name__ == "__main__":
    freeze_support()
    inf.bip, inf.db_bf, inf.th, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sleep, inf.balance, inf.brain, inf.custom_dir, inf.custom_words, inf.custom_lang  = createParser()
    print('-'*70,end='\n')
    print(Fore.GREEN+Style.BRIGHT+'Thank you very much: @iceland2k14 for his libraries!\033[0m')

    if test():
        print('\033[32m[I] TEST: OK! \033[0m')
    else:
        print('\033[32m[E] TEST: ERROR \033[0m')
        logger_err.error(('TEST: ERROR'))
        sys.exit()

    if inf.bip in ('32', '44', 'ETH', 'BTC'):
        pass
    else:
        print('\033[1;31m[E] Wrong BIP selected \033[0m')
        logger_err.error(('Wrong BIP selected'))
        sys.exit()

    if inf.bit in (128, 160, 192, 224, 256):
        pass          
    else:
        print('\033[1;31m[E] Wrong words selected \033[0m')
        logger_err.error(('Wrong words selected'))
        sys.exit()

    if inf.mode in ('s', 'e', 'g', 'c'):
        if (inf.mode == 's'):
            inf.mode_text = 'Standart'
        elif (inf.mode == 'e'):
            inf.mode_text = 'Mnemonic from Entropy'
        elif (inf.mode == 'g'):
            inf.mode_text = 'Game words'
        elif (inf.mode == 'c'):
            if inf.custom_dir == '':
                print('[E] NOT custom file')
                logger_err.error(('NOT custom file'))
                sys.exit()
            inf.mode_text = 'Custom words'
    else:
        print('\033[1;31m[E] Wrong mode selected')
        logger_err.error(('Wrong mode selected'))
        sys.exit()

    if inf.th < 1:
        print('\033[1;31m[E] The number of processes must be greater than 0 \033[0m')
        logger_err.error(('The number of processes must be greater than 0'))
        sys.exit()

    if inf.th > multiprocessing.cpu_count():
        print('\033[1;31m[I] The specified number of processes exceeds the allowed\033[0m')
        print('\033[1;31m[I] FIXED for the allowed number of processes\033[0m')
        inf.th = multiprocessing.cpu_count()

    print('-'*70,end='\n')
    print(f'[I] Version: {inf.version}')
    logger_info.info(f'Start HUNT version {inf.version}')
    print(f'[I] Total kernel of CPU: {multiprocessing.cpu_count()}')
    print(f'[I] Used kernel: {inf.th}')
    print(f'[I] Mode Search: BIP-{inf.bip} {inf.mode_text}')
    logger_info.info(f'[I] Mode Search: BIP-{inf.bip} {inf.mode_text}')
    print(f'[I] Database Bloom Filter: {inf.db_bf}')
    if inf.custom_dir != '': print(f'[I] Сustom dictionary: {inf.custom_dir}')
    if inf.custom_dir != '': print(f'[I] Сustom words: {inf.custom_words}')
    if inf.custom_dir != '': print(f'[I] Languages at work: {inf.custom_lang}')
    if inf.mode == 's' and inf.bip == 'ETH': print(f'[I] Languages at work: {inf.mnemonic_ETH}')
    else: print(f'[I] Languages at work: {inf.mnemonic_BTC}')
    
    print(f'[I] Work BIT: {inf.bit}')
    print(f'[I] Description client: {email.desc}')
    print(f'[I] Smooth start {inf.sleep} sec')

    if inf.mail: print('[I] Send mail: On')
    else: print('[I] Send mail: Off')
    if inf.balance: print('[I] Check balance BTC: On')
    else: print('[I] Check balance: Off')
    if inf.brain: print('[I] WrainWallet: On')
    else: print('[I] WrainWallet: Off')
    print('-'*70,end='\n')
    counter = Counter(0)
    tr = Counter(0)
    brain = Counter(0)
    count = Counter(0)
    count_nem = Counter(0)

    try:
        procs = [Process(target=run, name= str(i), args=(inf.bip, inf.db_bf, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.th, 
                                                         inf.sleep, inf.balance, inf.brain, inf.custom_dir, inf.custom_words, inf.custom_lang, count_nem, count, counter, tr, brain)) for i in range(inf.th)]
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        logger_info.info('[EXIT] Interrupted by the user.')
        sys.exit()
    try:
        for p in procs: p.start()
        for p in procs: p.join()
    except KeyboardInterrupt:
        print('\n[EXIT] Interrupted by the user.')
        logger_info.info('[EXIT] Interrupted by the user.')
        sys.exit()
    