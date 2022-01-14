# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
"""
@author: Noname400
"""

from consts import *


def reverse_string(s):
    return s[::-1]

def bw(text, brain, counter):
    f1 = []
    f2 = []
    f3 = []
    no_bs = text.replace(' ', '')
    text_rev = reverse_string(text)
    f1.append(secp256k1_lib.get_sha256(text))
    f1.append(secp256k1_lib.get_sha256(secp256k1_lib.get_sha256(text)))
    f1.append(secp256k1_lib.get_sha256(text_rev))
    f1.append(secp256k1_lib.get_sha256(secp256k1_lib.get_sha256(text_rev)))
    f1.append(secp256k1_lib.get_sha256(no_bs))
    f1.append(secp256k1_lib.get_sha256(secp256k1_lib.get_sha256(no_bs)))
    for res in f1:
        f2.append(secp256k1_lib.privatekey_to_h160(0, True, int.from_bytes(res, "big")).hex())
        f2.append(secp256k1_lib.privatekey_to_h160(0, False, int.from_bytes(res, "big")).hex())
    for res in f2:
        if inf.debug:
            print(f'[D][BRAIN] {res} {text}')
            logger_info.info(f'[D][BRAIN] {res} {text}')
        for res in f2:
            if res in inf.bf:
                print(f'[F][Brain] {res} | {text}')
                logger_info.info(f'[F][Brain] {res} | {text}')
                counter.increment()
            brain.increment12()

def get_balance(address):
    time.sleep(11) 
    if inf.bip == 'ETH':
        try:
            response = requests.get(inf.ETH_bal_server[1] + '0x' + address)
            return int(response.json()['result'])
        except:
            print('[E][ETH] NOT connect balance server')
            logger_err.error('[E][ETH] NOT connect balance server')
            return -1
    else:
        try:
            if inf.bal_srv_count == 0:
                response = requests.get(inf.bal_server[inf.bal_srv_count] + str(address))
                return int(response.json()['n_tx']), float(response.json()['balance'])
            elif inf.bal_srv_count == 1:
                response = requests.get(inf.bal_server[inf.bal_srv_count] + str(address))
                return int(response.json()['txApperances']), float(response.json()['balance'])
            elif inf.bal_srv_count == 2:
                response = requests.get(inf.bal_server[inf.bal_srv_count] + str(address))
                return int(response.json()['data']['total_txs']), float(response.json()['data']['balance'])
            elif inf.bal_srv_count == 3:
                response = requests.get(inf.bal_server[inf.bal_srv_count] + str(address))
                return int(response.json()['n_tx']), float(response.json()['final_balance'])
        except:
            logger_err.error('[E][BTC, 44, 32] NOT connect balance server')
            print('[E][BTC, 44, 32] NOT connect balance server')
            if inf.bal_err < 10:
                inf.bal_err += 1
            else:
                if inf.bal_srv_count < 3:
                    inf.bal_srv_count += 1
                else:
                    inf.bal_srv_count = 0
            inf.bal_all_err += 1
            if inf.bal_all_err == 40:
                inf.balance = False
            return -1

def load_BF(load, tr):
    try:
        fp = open(load, 'rb')
    except FileNotFoundError:
        print(f'\033[1;31m\n[E] File: {load} not found. \033[0m')
        logger_err.error(f'[E] File: {load} not found.')
        sys.exit()
    else:
        n_int = int(multiprocessing.current_process().name)
        time.sleep(inf.sleep*n_int)
        inf.bf = BloomFilter.load(fp)
        tr.increment()

def send_email(text):
    subject = ''
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = str(inf.dt_now) + ' | ' + text
    subject = email.subject + ' description -> ' + email.desc
    BODY:str = '\r\n'.join(('From: %s' % email.from_addr, 'To: %s' % email.to_addr, 'Subject: %s' % subject, '', text)).encode('utf-8')
    try:
        server = smtplib.SMTP(email.host,email.port)
    except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
        print("\033[1;31m \n[E] could not connect to the mail server \033[0m")
        logger_err.error('[E] could not connect to the mail server')
        inf.mail_err += 1
        if inf.mail_err >= 3:
            inf.mail = False
    except ConnectionRefusedError:
        print("\033[1;31m \n[E] could not connect to the mail server \033[0m")
        logger_err.error('[E] could not connect to the mail server')
        inf.mail_err += 1
        if inf.mail_err >= 3:
            inf.mail = False
    else:
        try:
            server.login(email.from_addr, email.password)
        except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
            print("\033[1;31m \n[E] could not connect to the mail server \033[0m")
            logger_err.error('[E] could not connect to the mail server')
            inf.mail_err += 1
            if inf.mail_err >= 3:
                inf.mail = False
        else:
            try:
                server.sendmail(email.from_addr, email.to_addr, BODY)
            except UnicodeError:
                print('\033[1;31m \n[E] Error Encode UTF-8 \033[0m')
                logger_err.error('[E] Error Encode UTF-8')
            else:
                server.quit()

def save_rezult(name_file,text:str):
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = inf.dt_now+' | '+ text
    try:
        f_rez = open(name_file, 'a', encoding='utf-8')
    except FileNotFoundError:
        print(f'\n[E] file {name_file} not found. \033[0m')
        logger_err.error(f'[E] file {name_file} not found.')
    else:
        try:
            tf:str = text+'\n'
            f_rez.write(tf)
        except UnicodeError:
            print('\033[1;31m\n[E] Error Encode UTF-8 \033[0m')
            logger_err.error('[E] Error Encode UTF-8')
        finally:
            f_rez.close()

def b32(mnemo, seed, counter, count):
    bip32 = BIP32.from_seed(seed)
    for path in inf.l32:
        for num1 in range(1):
            for t in inf.l32_:
                for num2 in range(20):
                    for t1 in inf.l32_:
                        patchs = f"{path}{num1}{t}/{num2}{t1}"
                        pvk = bip32.get_privkey_from_path(patchs)
                        pvk_int = int(pvk.hex(),16)
                        bip32_h160_cs = secp256k1_lib.privatekey_to_h160(1, True, pvk_int)
                        bip32_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                        bip32_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                        if inf.debug > 0:
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip32_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip32_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip32_h160_cs)
                            addr_cbc = secp256k1_lib.hash_to_address(2, False, bip32_h160_c)
                            if inf.debug > 0:
                                print(f'\n[D][Mode 32] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                logger_dbg.debug(f'\n[D][Mode 32] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                        if (bip32_h160_c.hex() in inf.bf) or (bip32_h160_uc.hex() in inf.bf):
                            if inf.debug > 0:
                                print(f'[D][F][Mode 32] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                logger_dbg.debug(f'[D][F][Mode 32] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                            if inf.debug < 1:
                                addr_c = secp256k1_lib.hash_to_address(0, False, bip32_h160_c)
                                addr_uc = secp256k1_lib.hash_to_address(0, False, bip32_h160_uc)
                                addr_cs = secp256k1_lib.hash_to_address(1, False, bip32_h160_cs)
                                addr_cbc = secp256k1_lib.hash_to_address(2, False, bip32_h160_c)
                                if inf.balance:
                                    tx1, b1 = get_balance(addr_c)
                                    tx2, b2 = get_balance(addr_uc)
                                    tx3, b3 = get_balance(addr_cs)
                                    tx4, b4 = get_balance(addr_cbc)
                                    if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                        print(f'\n[F][Mode 32] Found transaction! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                        logger_found.info(f'[F][Mode 32] Found transaction! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                    if (b1 > 0) or (b2 > 0) or (b3 > 0) or (b4 > 0):
                                        print(f'\n[F][Mode 32] Found address in balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        logger_found.info(f'[F][Mode 32] Found address in balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        if inf.mail:
                                            send_email(f'[F][Mode 32] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')    
                                        counter.increment()
                                    else:
                                        print(f'\n[F][Mode 32] Found address balance 0.0 {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        logger_found.info(f'[F][Mode 32] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        if inf.mail:
                                            send_email(f'[F][Mode 32] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                else:
                                    print(f'\n[F][Mode 32] Found address {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    logger_found.info(f'[F][Mode 32] Found address {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    if inf.mail:
                                        send_email(f'[F][Mode 32] Found address {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    counter.increment()
                        count.increment4()

def bETH(mnemo, seed, counter, count):
    w = BIP32.from_seed(seed)
    for p in inf.leth:
        for nom2 in range(1):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(50):
                    patchs = f"m/44'/{p}'/{nom2}'/{nom3}/{nom}"
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    addr = secp256k1_lib.privatekey_to_ETH_address(pvk_int)
                    if inf.debug > 0:
                        print(f"[D][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}")
                        logger_dbg.debug(f"[D][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}")
                    if addr in inf.bf:
                        if inf.debug > 0:
                            print(f'[D][F][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                            logger_dbg.debug(f'[D][F][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                        if inf.debug < 1:
                            if inf.balance:
                                b1 = get_balance(addr)
                                if (b1 > 0):
                                    logger_found.info(f'[F][Mode ETH] Found address in balance! {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                                    if inf.mail:
                                        send_email(f'[F][Mode ETH] Found address in balance! {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                                    counter.increment()
                                else:
                                    print(f'\n[F][Mode ETH] Found address balance 0.0: {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr}')
                                    logger_found.info(f'[F][Mode ETH] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | addr: 0x{addr}')
                                    if inf.mail:
                                        send_email(f'[F][Mode ETH] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | addr: 0x{addr}')
                            else:
                                print(f'\n[F][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                                logger_found.info(f'[F][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()}| {seed.hex()} | addr: 0x{addr}')
                                if inf.mail:
                                    send_email(f'[F][Mode ETH] {patchs} | {mnemo} | PVK:{pvk.hex()} | {seed.hex()} | addr: 0x{addr}')
                                counter.increment()
                    count.increment()

def b44(mnemo, seed, counter, count):
    w = BIP32.from_seed(seed)
    for p in inf.l44:
        for nom2 in range(1):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = f"m/44'/{p}'/{nom2}'/{nom3}/{nom}"
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_cs = secp256k1_lib.privatekey_to_h160(1, True, pvk_int)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                    if inf.debug > 0 :
                        if p=='0':
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_cs)
                            addr_cbc = secp256k1_lib.hash_to_address(2, False, bip44_h160_c)
                            logger_dbg.debug(f'[D][P:{multiprocessing.current_process().name}] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                            logger_dbg.debug(f'[D] {bip44_h160_c.hex()}, {bip44_h160_uc.hex()}')
                            print(f'\n[D][P:{multiprocessing.current_process().name}] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                            print(f'[D] {bip44_h160_c.hex()},{bip44_h160_uc.hex()}')
                        else:
                            logger_dbg.debug(f'[D][P:{multiprocessing.current_process().name}] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}')
                            print(f'\n[D] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}')
                    if (bip44_h160_c.hex() in inf.bf) or (bip44_h160_uc.hex() in inf.bf):
                        if inf.debug > 0:
                            if p=='0':
                                logger_dbg.debug(f'[D][F][P:{multiprocessing.current_process().name}] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr 1:{addr_c} | addr 2:{addr_uc} | addr 3:{addr_cs} | addr 4:{addr_cbc}')
                            else:
                                logger_dbg.debug(f'[D][F][P:{multiprocessing.current_process().name}] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}')
                        if inf.debug < 1:
                            if p=='0':
                                addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                                addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                                addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_cs)
                                addr_cbc = secp256k1_lib.hash_to_address(2, False, bip44_h160_c)
                                if inf.balance:
                                    tx1, b1 = get_balance(addr_c)
                                    tx2, b2 = get_balance(addr_uc)
                                    tx3, b3 = get_balance(addr_cs)
                                    tx4, b4 = get_balance(addr_cbc)
                                    if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                        print(f'\n[F][Mode 44 BTC] Found transaction! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                        logger_found.info(f'\n[F][Mode 44 BTC] Found transaction! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                    if (b1 > 0) or (b2 > 0) or (b3 > 0) or (b4 > 0):
                                        print(f'\n[F][Mode 44 BTC] Found address in balance! {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        logger_found.info(f'[F][Mode 44 BTC] Found address in balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        if inf.mail:
                                            send_email(f'[F][Mode 44 BTC] Found address in balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')    
                                        counter.increment()
                                    else:
                                        print(f'\n[F][Mode 44 BTC] Found address balance 0.0 {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        logger_found.info(f'[F][Mode 44 BTC] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                        if inf.mail:
                                            send_email(f'[F][Mode 44 BTC] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                else:
                                    print(f'\n[F][Mode 44 BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    logger_found.info(f'[F][Mode 44 BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    if inf.mail:
                                        send_email(f'[F][Mode 44 BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    counter.increment()
                            else:
                                print(f"[F][Mode 44 not BTC address] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}")
                                logger_found.info(f'[F][Mode 44 not BTC address] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | Hash160 compress:{bip44_h160_c.hex()} | Hash160 uncompress:{bip44_h160_uc.hex()}')
                                if inf.mail:
                                    send_email(f'[F][Mode 44 not BTC address] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | Hash160 compress:{bip44_h160_c.hex()} | Hash160 uncompress:{bip44_h160_uc.hex()}')
                                counter.increment()
                    count.increment4()

def bBTC(mnemo, seed, counter, count):
    w = BIP32.from_seed(seed)
    for bip_ in inf.lbtc:
        for nom2 in range(1):
            for nom3 in range(2):
                for nom in range(20):
                    patchs = f"m/{bip_}'/0'/{nom2}'/{nom3}/{nom}"
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_cs = secp256k1_lib.privatekey_to_h160(1, True, pvk_int)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                    if inf.debug > 0:
                        addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                        addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                        addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_cs)
                        addr_cbc = secp256k1_lib.hash_to_address(2, False, bip44_h160_c)
                        print(f'\n[D][Mode BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                        print(bip_,bip44_h160_c.hex(),bip44_h160_uc.hex())
                        logger_dbg.debug(f'[D][Mode BTC][P:{multiprocessing.current_process().name}] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                        logger_dbg.debug(f'[D][Mode BTC] bip:{bip_}, {bip44_h160_c.hex()}, {bip44_h160_uc.hex()}')
                    if (bip44_h160_c.hex() in inf.bf) or (bip44_h160_uc.hex() in inf.bf):
                        if inf.debug > 0:
                            logger_dbg.debug(f'[D][F][Mode BTC][P:{multiprocessing.current_process().name}] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                        if inf.debug < 1:
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_cs)
                            addr_cbc = secp256k1_lib.hash_to_address(2, False, bip44_h160_c)
                            if inf.balance:
                                tx1, b1 = get_balance(addr_c)
                                tx2, b2 = get_balance(addr_uc)
                                tx3, b3 = get_balance(addr_cs)
                                tx4, b4 = get_balance(addr_cbc)
                                if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                    print(f'[F][Mode BTC] Found transaction! {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                    logger_found.info(f'[F][Mode BTC] Found transaction! {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_cbc}:{b4}')
                                if (b1 > 0) or (b2 > 0) or (b3 > 0) or (b4 > 0):
                                    print(f'\n[F][Mode BTC] Found balance! {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    logger_found.info(f'[F][Mode BTC] Found balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    if inf.mail:
                                        send_email(f'[F][Mode BTC] Found balance! {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')    
                                    counter.increment()
                                else:
                                    print(f'\n[F False][Mode BTC] Found address balance 0.0  {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    logger_found.info(f'[F False][Mode BTC] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                    if inf.mail:
                                        send_email(f'[F False][Mode BTC] Found address balance 0.0 {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                            else:
                                print(f'\n[F][Mode BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                logger_found.info(f'[F][Mode BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                if inf.mail:
                                    send_email(f'[F][Mode BTC] {patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_cbc}')
                                counter.increment()
                    count.increment4()

def nnmnem(mem):
    if inf.mode == 'e':
        mnemo:Mnemonic = Mnemonic(mem)
        if inf.bit == 128: bit = 16
        if inf.bit == 160: bit = 20
        if inf.bit == 192: bit = 24
        if inf.bit == 224: bit = 28
        if inf.bit == 256: bit = 32
        ran = secrets.token_hex(bit)
        mnemonic = mnemo.to_mnemonic(bytes.fromhex(ran))
        seed_bytes = mnemo.to_seed(mnemonic, passphrase='')
    elif inf.mode =='g':
        mnemonic = ''
        mnemo:Mnemonic = Mnemonic(mem)
        rw = randint(1,25)
        mnemonic = ' '.join(random.choice(inf.game_list) for i in range(rw))
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
    elif inf.mode =='c':
        mnemonic = ''
        mnemo:Mnemonic = Mnemonic(mem)
        rw = inf.custom_words
        mnemonic = ' '.join(random.choice(inf.custom_list) for i in range(rw))
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
    else:
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic:str = mnemo.generate(strength=inf.bit)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
 
    if inf.debug==1:
        mnemo = Mnemonic('english')
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        print(f'Debug Mnemonic : {mnemonic}')
        print(f'Debug SEED : {seed_bytes.hex()}')
        logger_dbg.debug(f'[D] Debug Mnemonic : {mnemonic}')
        logger_dbg.debug(f'[D] Debug SEED : {seed_bytes.hex()}')
    if inf.debug==2:
        print('Debug Mnemonic : '+ mnemonic)
        print(f'Debug SEED : {seed_bytes.hex()}')
        logger_dbg.debug(f'[D] Debug Mnemonic : {mnemonic}')
        logger_dbg.debug(f'[D] Debug SEED : {seed_bytes.hex()}')
    return mnemonic, seed_bytes

def test():
    print('-'*70,end='\n')
    print('DEPENDENCY TESTING:')
    if platform.system().lower().startswith('win'):
        dllfile = 'ice_secp256k1.dll'
        if os.path.isfile(dllfile) == True:
            pass
        else:
            print(f'\033[1;31m File {dllfile} not found \033[0m')
            logger_err.error(f'File {dllfile} not found')
            
            
    elif platform.system().lower().startswith('lin'):
        dllfile = 'ice_secp256k1.so'
        if os.path.isfile(dllfile) == True:
            pass
        else:
            print('\033[1;31m File {} not found \033[0m'.format(dllfile))
            logger_err.error(f'File {dllfile} not found')
    else:
        print('\033[1;31m * Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working \033[0m')
        logger_err.error(f'* Unsupported Platform currently for ctypes dll method. Only [Windows and Linux] is working')
        
        sys.exit()
    mnemo:Mnemonic = Mnemonic('english')
    mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
    seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
    if seed_bytes.hex() !='bd85556143de177ed9781ac3b24ba33d0bc4f8d6f34d9eaa1d9b8ab0ee3a7e84d42638b520043234bcedb4e869464b9f964e7e8dbf1588395f7a7782588ae664':
        print('\033[1;31m ERROR: Generate mnemonic \033[0m')
        print('\033[1;31m Please reinstall https://github.com/trezor/python-mnemonic \033[0m')
        logger_err.error(f'ERROR: Generate mnemonic')
        logger_err.error(f'Please reinstall https://github.com/trezor/python-mnemonic')
        sys.exit()
    bip32 = BIP32.from_seed(seed_bytes)
    patchs = "m/0'/0'/0"
    pvk = bip32.get_privkey_from_path(patchs)
    pvk_int = int(pvk.hex(),16)
    bip_hash_c = secp256k1_lib.privatekey_to_h160(0,True,pvk_int)
    bip_hash_uc = secp256k1_lib.privatekey_to_h160(0,False,pvk_int)
    addr_c = secp256k1_lib.hash_to_address(0,True,bip_hash_c)
    addr_uc = secp256k1_lib.hash_to_address(0,False,bip_hash_uc)
    if (addr_c != '1JiG9xbyAPNfX8p4M6qxE6PwyibnqARkuq') or (addr_uc != '1EHciAwg1thir7Gvj5cbrsyf3JQbxHmWMW'):
        print('\033[1;31m ERROR: Convert address from mnemonic')
        print('\033[1;31m Please recopy https://github.com/iceland2k14/secp256k1 \033[0m')
        logger_err.error(f'ERROR: Convert address from mnemonic')
        logger_err.error(f'Please recopy https://github.com/iceland2k14/secp256k1')
        sys.exit()
    return True