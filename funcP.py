# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
"""
@author: Noname400
"""

from random import randint
from consts import *

def get_balance(address):
    time.sleep(1) 
    if inf.bip == 'ETH':
        try:
            response = requests.get(inf.ETH_bal_server[1] + '0x' + address)
            return int(response.json()['result'])
        except:
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

def load_BF(load, tr1):
    try:
        fp = open(load, 'rb')
    except FileNotFoundError:
        print('\033[1;31m\n[E] File: '+ load + ' not found. \033[0m')
        sys.exit()
    else:
        n_int = int(multiprocessing.current_process().name)
        time.sleep(inf.sleep*n_int)
        inf.bf = BloomFilter.load(fp)
        tr1.increment()
        return tr1.value()

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
        inf.mail_err += 1
        if inf.mail_err >= 3:
            inf.mail = False
    except ConnectionRefusedError:
        print("\033[1;31m \n[E] could not connect to the mail server \033[0m")
        inf.mail_err += 1
        if inf.mail_err >= 3:
            inf.mail = False
    else:
        try:
            server.login(email.from_addr, email.password)
        except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
            print("\033[1;31m \n[E] could not connect to the mail server \033[0m")
            inf.mail_err += 1
            if inf.mail_err >= 3:
                inf.mail = False
        else:
            try:
                server.sendmail(email.from_addr, email.to_addr, BODY)
            except UnicodeError:
                print('\033[1;31m \n[E] Error Encode UTF-8 \033[0m')
            else:
                server.quit()

def save_rezult(name_file,text:str):
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = inf.dt_now+' | '+ text
    try:
        f_rez = open(name_file, 'a', encoding='utf-8')
    except FileNotFoundError:
        print('\n[E] file '+name_file+' not found. \033[0m')
    else:
        try:
            tf:str = text+'\n'
            f_rez.write(tf)
        except UnicodeError:
            print('\033[1;31m\n[E] Error Encode UTF-8 \033[0m')
        finally:
            f_rez.close()

def b32(mnemo, seed, counter):
    bip32 = BIP32.from_seed(seed)
    for path in inf.l32:
        for num1 in range(2):
            for t in inf.l32_:
                for num2 in range(20):
                    for t1 in inf.l32_:
                        patchs = path+str(num1)+t+"/"+str(num2)+t1
                        pvk = bip32.get_privkey_from_path(patchs)
                        pvk_int = int(pvk.hex(),16)
                        bip32_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                        bip32_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                        if inf.debug > 0:
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip32_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip32_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip32_h160_c)
                            addr_ucs = secp256k1_lib.hash_to_address(1, False, bip32_h160_uc)
                            print(f'\n[I] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                        if (bip32_h160_c.hex() in inf.bf) or (bip32_h160_uc.hex() in inf.bf):
                            if inf.debug > 0:
                                save_rezult('dbg32.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                            if inf.debug < 1:
                                addr_c = secp256k1_lib.hash_to_address(0, False, bip32_h160_c)
                                addr_uc = secp256k1_lib.hash_to_address(0, False, bip32_h160_uc)
                                addr_cs = secp256k1_lib.hash_to_address(1, False, bip32_h160_c)
                                addr_ucs = secp256k1_lib.hash_to_address(1, False, bip32_h160_uc)
                                if inf.balance:
                                    tx1, b1 = get_balance(addr_c)
                                    tx2, b2 = get_balance(addr_uc)
                                    tx3, b3 = get_balance(addr_cs)
                                    tx4, b4 = get_balance(addr_ucs)
                                    if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                        print(f'\n[W] Found transaction! | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                    print(f'\n[W] Found address | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                    if (b1 > 0.00000000) or (b2 > 0.00000000) or (b3 > 0.00000000) or (b4 > 0.00000000):
                                        print(f'\n[W] Found address in balance | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                        save_rezult('found.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | {addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')
                                        if inf.mail:
                                            send_email(f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')    
                                        counter.increment()
                                    else:
                                        if (b1 < 0) or (b2 < 0) or (b3 < 0) or (b4 < 0): 
                                            print(f'\n[W] Found address | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                            save_rezult(f'log.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')
                                            if inf.mail:
                                                send_email(f'log.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')
                                            counter.increment()
                                        print('[W] Found address balance 0.0')
                                        #continue
                                else:
                                    print(f'\n[W] Found address | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                    save_rezult(f'found.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')
                                    if inf.mail:
                                        send_email(f'found.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 32')
                                    counter.increment()
                        inf.count = inf.count + 4

def bETH(mnemo, seed, counter):
    w = BIP32.from_seed(seed)
    for p in inf.leth:
        for nom2 in range(2):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    addr = secp256k1_lib.privatekey_to_ETH_address(pvk_int)
                    if inf.debug > 0:
                        print(f"path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr}")
                    if addr in inf.bf:
                        if inf.debug > 0:
                            save_rezult('dbgETH.txt',f'path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr}')
                        if inf.debug < 1:
                            if inf.balance:
                                b1 = get_balance(addr)
                                print(f'\n[W] Found address | 0x{addr}: {b1}')
                                if (b1 > 0):
                                    save_rezult('found.txt',f'path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                    if inf.mail:
                                        send_email(f'found.txt',f'path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                    counter.increment()
                                else:
                                    if (b1 < 0): 
                                        print(f'\n[W] Found address | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | {addr}')
                                        save_rezult(f'log.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                        if inf.mail:
                                            send_email(f'log.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                        counter.increment()
                                    print('[W] Found address balance 0.0')

                            else:
                                print(f'\n[W] Found address | path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr}')
                                save_rezult('found.txt',f'path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()}| SEED:{seed.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                if inf.mail:
                                    send_email(f'path:{patchs} | mnem:{mnemo} | PVK:{pvk.hex()} | SEED:{seed.hex()} | addr: 0x{addr} | BIP ETH/ETC')
                                counter.increment()
                    inf.count = inf.count + 1

def b44(mnemo, seed, counter):
    w = BIP32.from_seed(seed)
    for p in inf.l44:
        for nom2 in range(2):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                    if inf.debug > 0 :
                        if p=='0':
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_c)
                            addr_ucs = secp256k1_lib.hash_to_address(1, False, bip44_h160_uc)
                            print(f'\n[I] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                        else:
                            print(f'\n[I] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}')
                    if (bip44_h160_c.hex() in inf.bf) or (bip44_h160_uc.hex() in inf.bf):
                        if inf.debug > 0:
                            if p=='0':
                                save_rezult('dbg44_btc.txt',f"path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}")
                            else:
                                save_rezult('dbg44_other.txt',f"path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | HASH160 compress:{bip44_h160_c.hex()} | HASH160 uncompress:{bip44_h160_uc.hex()}")
                        if inf.debug < 1:
                            if p=='0':
                                addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                                addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                                addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_c)
                                addr_ucs = secp256k1_lib.hash_to_address(1, False, bip44_h160_uc)
                                if inf.balance:
                                    tx1, b1 = get_balance(addr_c)
                                    tx2, b2 = get_balance(addr_uc)
                                    tx3, b3 = get_balance(addr_cs)
                                    tx4, b4 = get_balance(addr_ucs)
                                    if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                        print(f'\n[W] Found transaction! | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                    print(f'\n[W] Found address | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                    if (b1 > 0.00000000) or (b2 > 0.00000000) or (b3 > 0.00000000) or (b4 > 0.00000000):
                                        print(f'\n[W] Found address in balance | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                        save_rezult('found.txt',f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 44')
                                        if inf.mail:
                                            send_email(f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 44')    
                                        counter.increment()
                                    else:
                                        if (b1 < 0) or (b2 < 0) or (b3 < 0) or (b4 < 0): 
                                            print(f'\n[W] Found address | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs}')
                                            save_rezult(f'log.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BIP 44')
                                            if inf.mail:
                                                send_email(f'log.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BIP 44')
                                            counter.increment()
                                        print('[W] Found address balance 0.0')
                                else:
                                    print(f'\n[W] Found address | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                    save_rezult(f'found.txt',f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 44')
                                    if inf.mail:
                                        send_email(f'found.txt',f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs} | BIP 44')
                                    counter.increment()
                            else:
                                print(f'\n[W] Found address | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | Hash160 compress:{bip44_h160_c.hex()} | Hash160 uncompress:{bip44_h160_uc.hex()}')
                                save_rezult(f'found.txt',f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | Hash160 compress:{bip44_h160_c.hex()} | Hash160 uncompress:{bip44_h160_uc.hex()} | BIP 44')
                                if inf.mail:
                                    send_email(f'found.txt',f'{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | Hash160 compress:{bip44_h160_c.hex()} | Hash160 uncompress:{bip44_h160_uc.hex()} | BIP 44')
                                counter.increment()
                    inf.count = inf.count + 4

def bBTC(mnemo, seed, counter):
    pur = 0
    w = BIP32.from_seed(seed)
    for bip_ in inf.lbtc:
        if bip_ == "49": pur = 1
        else: pur = 0
        for nom2 in range(2):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/"+bip_+"'/0'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(pur, True, pvk_int)
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                    if inf.debug > 0:
                        addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                        addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                        addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_c)
                        addr_ucs = secp256k1_lib.hash_to_address(1, False, bip44_h160_uc)
                        print(f'\n[I] path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                        print(bip_,bip44_h160_c.hex(),bip44_h160_uc.hex())
                    if (bip44_h160_c.hex() in inf.bf) or (bip44_h160_uc.hex() in inf.bf):
                        if inf.debug > 0:
                            save_rezult('dbg32.txt',f'path:{patchs} | mnem:{mnemo} | SEED:{seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                        if inf.debug < 1:
                            addr_c = secp256k1_lib.hash_to_address(0, False, bip44_h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0, False, bip44_h160_uc)
                            addr_cs = secp256k1_lib.hash_to_address(1, False, bip44_h160_c)
                            addr_ucs = secp256k1_lib.hash_to_address(1, False, bip44_h160_uc)
                            if inf.balance:
                                tx1, b1 = get_balance(addr_c)
                                tx2, b2 = get_balance(addr_uc)
                                tx3, b3 = get_balance(addr_cs)
                                tx4, b4 = get_balance(addr_ucs)
                                if (tx1 > 0) or (tx2 > 0) or (tx3 > 0) or (tx4 > 0):
                                    print(f'\n[W] Found transaction! | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                print(f'\n[W] Found address | {addr_c}:{b1} | {addr_uc}:{b2} | {addr_cs}:{b3} | {addr_ucs}:{b4}')
                                if (b1 > 0.00000000) or (b2 > 0.00000000) or (b3 > 0.00000000) or (b4 > 0.00000000):
                                    print(f'\n[W] Found address in balance | mnem:{mnemo} | {seed.hex()} | PVK:{pvk.hex()} | addr compress:{addr_c} | addr uncompress:{addr_uc} | addr compress Segwit:{addr_cs} | addr uncompress Segwit:{addr_ucs}')
                                    save_rezult('found.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')
                                    if inf.mail:
                                        send_email(f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')    
                                    counter.increment()
                                else:
                                    if (b1 < 0) or (b2 < 0) or (b3 < 0) or (b4 < 0): 
                                        print(f'\n[W] Found address | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs}')
                                        save_rezult(f'log.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')
                                        if inf.mail:
                                            send_email(f'log.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')
                                        counter.increment()
                                    print('[W] Found address balance 0.0')
                            else:
                                print(f'\n[W] Found address | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs}')
                                save_rezult(f'found.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')
                                if inf.mail:
                                    send_email(f'found.txt',f'{patchs} | {mnemo} | {seed.hex()} | PVK:{pvk.hex()} | {addr_c} | {addr_uc} | {addr_cs} | {addr_ucs} | BTC mode')
                                counter.increment()
                    inf.count = inf.count + 4

def nnmnem(mem):
    if inf.mode == 'r1':
        mnemonic = ''
        rd=32
        if inf.bit > 64: rd = 64
        if inf.bit < 32: rd = 32
        #seed_bytes = os.urandom(rd)
        seed_bytes = secrets.token_bytes(rd)
    elif inf.mode =='r2':
        if inf.bit == 32: bit = 3
        if inf.bit == 64: bit = 6
        if inf.bit == 96: bit = 9
        if inf.bit == 128: bit = 12
        if inf.bit == 160: bit = 15
        if inf.bit == 192: bit = 18
        if inf.bit == 224: bit = 21
        if inf.bit == 256: bit = 24
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic = ''
        for wi in (range(bit)):
            r1 = random.randint(0, len(inf.r2_list)-1)
            if wi == bit-1:
                mnemonic = mnemonic + inf.r2_list[r1]
            else:
                mnemonic = mnemonic + inf.r2_list[r1]+' '
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
    elif inf.mode =='game':
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic = ''
        rw = randint(0,25)
        for wi in (range(rw)):
            r1 = random.randint(0, len(inf.game_list)-1)
            if wi == rw-1:
                mnemonic = mnemonic + inf.game_list[r1]
            else:
                mnemonic = mnemonic + inf.game_list[r1]+' '
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
        
    elif inf.mode =='custom':
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic = ''
        rw = inf.custom_words
        for wi in (range(rw)):
            r1 = random.randint(0, len(inf.custom_list)-1)
            if wi == rw-1:
                mnemonic = mnemonic + inf.custom_list[r1]
            else:
                mnemonic = mnemonic + inf.custom_list[r1]+' '
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
    else:
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic:str = mnemo.generate(strength=inf.bit)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
 
    if inf.debug==1:
        mnemo = Mnemonic('english')
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
        print('Debug SEED : {}'.format(seed_bytes.hex()))
    if inf.debug==2:
        #mnemo = Mnemonic(mem)
        print('Debug Mnemonic : '+ mnemonic)
        print('Debug SEED : {}'.format(seed_bytes.hex()))
        #seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
    return mnemonic, seed_bytes

def test():
    print('-'*70,end='\n')
    print('DEPENDENCY TESTING:')
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
    mnemo:Mnemonic = Mnemonic('english')
    mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
    seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
    if seed_bytes.hex() !='bd85556143de177ed9781ac3b24ba33d0bc4f8d6f34d9eaa1d9b8ab0ee3a7e84d42638b520043234bcedb4e869464b9f964e7e8dbf1588395f7a7782588ae664':
        print('\033[1;31m ERROR: Generate mnemonic \033[0m')
        print('\033[1;31m Please reinstall https://github.com/Noname400/mnemonic-for-hunt \033[0m')
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
        sys.exit()
    return True