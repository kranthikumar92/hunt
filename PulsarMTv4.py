# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-

from funcP import *
from consts import *


def createParser ():
    parser = argparse.ArgumentParser(description='Hunt to Mnemonic')
    parser.add_argument ('-b', '--bip', action='store', type=str, help='32, 44, ETH default bip32', default='32')
    parser.add_argument ('-db', '--database', action='store', type=str, help='File BF', default='')
    #parser.add_argument ('-dbp', '--database_puzzle', action='store', type=str, help='File pazzle', default='')
    parser.add_argument ('-th', '--threading', action='store', type=int, help='threading', default='1')
    parser.add_argument ('-m', '--mode', action='store', type=str, help='mode s or r', default='s')
    parser.add_argument ('-des', '--desc', action='store', type=str, help='description', default='local')
    parser.add_argument ('-bit', '--bit', action='store', type=int, help='32, 64, 96, 128, 160, 192, 224, 256', default=128)
    parser.add_argument ('-dbg', '--debug', action='store', type=int, help='debug 0 1 2', default=0)
    parser.add_argument ('-em', '--mail', action='store', type=str, help='send mail or not ', default='no')
    parser.add_argument ('-sc', '--sock', action='store', type=str, help='send statistic to server ', default='no')
    parser.add_argument ('-sl', '--sleep', action='store', type=int, help='pause start (sec)', default='3')
    return parser.parse_args().bip, parser.parse_args().database, parser.parse_args().threading, parser.parse_args().mode, \
        parser.parse_args().desc, parser.parse_args().bit, parser.parse_args().debug, parser.parse_args().mail, parser.parse_args().sock, parser.parse_args().sleep

def run(bip, db_bf, mode, desc, bit, debug, mail, sockets, th, sleep,  counter, tr):
    inf.uid = str(uuid.UUID(int=uuid.getnode())).encode('utf-8')[24:]
    inf.db_bf = db_bf
    # inf.db_puzle=db_puzle
    # inf.puzle = puzle
    inf.mode=mode
    email.desc=desc
    inf.bit=bit
    inf.debug=debug
    inf.mail=mail
    inf.sockets=sockets
    inf.th = th
    inf.sleep = sleep
    ind:int = 1
    soc_count = 0
    load_BF(inf.db_bf, tr)
    #if inf.puzle: load_btc30(inf.db_puzle)
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
            speed = int((inf.count/st)*tr.value())
            total = inf.count*ind*tr.value()
            mm = ind*len(inf.mnemonic_lang)*tr.value()
            if multiprocessing.current_process().name == '0':
                print('\033[1;33m> Mnemonic: {:d} | Total keys {:d} | Speed {:d} key/s | Found {:d} \033[0m'.format(mm, total,speed, counter.value()),flush=True,end='\r')
                if (inf.sockets == 'yes') and (soc_count > 30):
                    send_stat(speed,total,counter.value())
                    soc_count = 0
            ind +=1
            soc_count += 1
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()

if __name__ == "__main__":
    inf.bip, inf.db_bf, inf.th, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sockets, inf.sleep  = createParser()
    inf.uid = str(uuid.UUID(int=uuid.getnode())).encode('utf-8')[24:]
    print('-'*70,end='\n')
    print(Fore.GREEN+Style.BRIGHT+'Thank you very much: @iceland2k14 for his libraries!\033[0m')

    if test():
        print('\033[32m TEST: OK! \033[0m')
    else:
        print('\033[32m TEST: ERROR \033[0m')

    if inf.bip in ('32', '44', 'ETH'):
        pass
    else:
        print('\033[1;31m Wrong BIP selected \033[0m')
        sys.exit()

    if inf.mail !='yes': inf.mail='no'

    if inf.sockets !='yes': inf.sockets='no'

    #if (inf.db_puzle !=""): inf.puzle = True

    if inf.bip =="ETH": inf.puzle = False

    if inf.bit in (128, 160, 192, 224, 256):
        pass          
    else:
        print('\033[1;31m Wrong words selected \033[0m')
        sys.exit()

    if inf.mode in ('s', 'r1', 'r2'):
        if (inf.mode == 's'):
            inf.mode_text = 'Standart'
        elif (inf.mode == 'r1'):
            inf.mode_text = 'Random'
        elif (inf.mode == 'r2'):
            inf.mode_text = 'Random test'
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

    print('-'*70,end='\n')
    print('* Version: {} '.format(inf.version))
    print('* Identificator system: {}'.format(inf.uid.decode("utf-8")))
    print('* Total kernel of CPU: {} '.format(multiprocessing.cpu_count()))
    print('* Used kernel: {} '.format(inf.th))
    print('* Mode Search: BIP-{} {} '.format (inf.bip, inf.mode_text))
    print('* Database Bloom Filter: {} '.format (inf.db_bf))
    #if inf.puzle: print('* Database Pazzle ~30BTC: {} '.format (inf.db_puzle))
    print('* Languages at work: {} '.format(inf.mnemonic_lang))
    print('* Work BIT: {} '.format(inf.bit))
    print('* Description client: {} '.format(email.desc))
    print('* Smooth start {} sec'.format(inf.sleep))

    if inf.mail == 'yes': print('* Send mail: On')
    else: print('* Send mail: Off')
    if inf.sockets == 'yes':
        print('* Send Statistic to server: On')
    else:
        print('* Send Statistic to server: Off')
    print('-'*70,end='\n')
    counter = Counter(0)
    tr = Counter(0)

    try:
        procs = [Process(target=run, name= str(i), args=(inf.bip, inf.db_bf, inf.mode, email.desc, inf.bit, inf.debug, inf.mail, inf.sockets, inf.th, inf.sleep, counter, tr,)) for i in range(inf.th)]
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()
    try:
        for p in procs: p.start()
        for p in procs: p.join()
    except KeyboardInterrupt:
        print('\n'+'Interrupted by the user.')
        sys.exit()
    