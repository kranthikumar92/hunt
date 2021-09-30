# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
from time import sleep
from consts import *


class Counter(object):
    def __init__(self, initval=0):
        self.val = Value('i', initval)
        self.lock = Lock()
    def increment(self):
        with self.lock:
            self.val.value += 1
    def value(self):
        with self.lock:
            return self.val.value

def load_BF(load):
    try:
        fp = open(load, 'rb')
    except FileNotFoundError:
        print('\033[1;31m \n'+'File: '+ load + ' not found. \033[0m')
        sys.exit()
    else:
        inf.bf = BloomFilter.load(fp)
        print('* Bloom Filter Loaded...')

def load_btc30(load):
    try:
        fp = open(load, 'r')
    except FileNotFoundError:
        print('\033[1;31m \n'+'File: '+load+' not found. \033[0m')
        sys.exit()
    else:
        lines = fp.readlines()
        inf.leth = [line.rstrip('\n') for line in lines]
        fp.close()
        print('* File address pazzle BTC~30 Loaded.')

def send_email(text):
    subject = ''
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = str(inf.dt_now) + ' | ' + text
    subject = email.subject + ' description -> ' + email.des_mail
    BODY:str = '\r\n'.join(('From: %s' % email.from_addr, 'To: %s' % email.to_addr, 'Subject: %s' % subject, '', text)).encode('utf-8')
    try:
        server = smtplib.SMTP(email.host,email.port)
    except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
        print("\033[1;31m \n[*] could not connect to the mail server \033[0m")
        inf.mail_nom += 1
        if inf.mail_nom >= 3:
            inf.mail = 'no'
    except ConnectionRefusedError:
        print("\033[1;31m \n[*] could not connect to the mail server \033[0m")
        inf.mail_nom += 1
        if inf.mail_nom >= 3:
            inf.mail = 'no'
    else:
        server.login(email.from_addr, email.password)
        try:
            server.sendmail(email.from_addr, email.to_addr, BODY)
        except UnicodeError:
            print('\033[1;31m \n[*] Error Encode UTF-8 \033[0m')
        else:
            server.quit()

def save_rezult(text:str):
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = inf.dt_now+' | '+ text
    try:
        f_rez = open('rezult.txt', 'a', encoding='utf-8')
    except FileNotFoundError:
        print('\n'+'file rezult.txt not found. \033[0m')
    else:
        try:
            tf:str = text+'\n'
            f_rez.write(tf)
        except UnicodeError:
            print('\033[1;31m \n'+'Error Encode UTF-8 \033[0m')
        finally:
            f_rez.close()

def send_stat(speed,total,found):
    b=b','
    uid = str(inf.uid).encode('utf-8')
    name = email.desc.encode('utf-8')
    mode = str(inf.bip).encode('utf-8')
    thread = str(inf.th).encode('utf-8')
    speed = str(speed).encode('utf-8')
    total = str(total).encode('utf-8')
    found = str(found).encode('utf-8')
    time_t = datetime.datetime.now()
    time_b = time_t.strftime("%y/%m/%d %H:%M").encode('utf-8')
    ver = inf.version
    work = b'Worker online'
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_sock.connect((sockets.server, sockets.port))
        client_sock.sendall(uid+b+name+b+mode+b+thread+b+speed+b+total+b+found+b+time_b+b+work)
    except (UnboundLocalError, ConnectionResetError, ConnectionError) as msg:
        print("\033[1;31m \nSocket creation error. Send Statictic Stop! \033[0m")
        inf.sockets_nom += 1
        if inf.sockets_nom >= 3:
            inf.sockets = 'no'
    else:
        data = client_sock.recv(1024)
        client_sock.close()
        return data

def b32(mnemo, seed, counter):
    bip32 = BIP32.from_seed(seed)
    for path in inf.l32:
        for num1 in range(2):
            for t in inf.l32_:
                for num2 in range(30):
                    for t1 in inf.l32_:
                        patchs = path+str(num1)+t+"/"+str(num2)+t1
                        pk_c = bip32.get_pubkey_from_path(patchs)
                        pk_uc = PublicKey(pk_c).format(False)
                        bip32_h160_c = CryptoUtils.Hash160(pk_c).hex()
                        bip32_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
                        if inf.debug > 0:
                            bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                            bip_addr_uc = P2PKH.ToAddress(pk_uc,net_addr_ver=b"\x00")
                            print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip32_h160_c,bip_addr_c,bip32_h160_uc,bip_addr_uc))
                        if bip32_h160_c in inf.list30:
                            print('\n-------------------------- Found --------------------------')
                            bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                            res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+bip_addr_c+' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                            save_rezult(res)
                            if inf.mail == 'yes':
                                send_email(res)
                        inf.count = inf.count + 1
                        if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                            if inf.debug < 1:
                                print("\033[32m \n Init Rescan... \n \033[0m")
                                save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                                if re32(bip32,mnemo,seed,path): counter.increment()
                                print("\033[32m \n Finish Rescan... \n \033[0m")
                        inf.count = inf.count + 2

def bETH(mnemo, seed, counter):
    w = BIP32.from_seed(seed)
    for p in inf.leth:
        for nom2 in range(4):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(40):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    addr = inf.privatekey_to_ETH_address(pvk_int)
                    if inf.debug > 0:
                        print("{} | {} | {} | {}".format(patchs,mnemo,seed.hex(),addr))
                    if addr in inf.bf:
                        if inf.debug < 1:
                            print("\033[32m \n Init Rescan... \n \033[0m")
                            save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                            if reETH(w,mnemo,seed,"m/44'/"+p+"'/"): counter.increment()
                            print("\033[32m \n Finish Rescan... \n \033[0m")
                    inf.count = inf.count + 1

def b44(mnemo, seed, counter):
    w = BIP32.from_seed(seed)
    for p in inf.l44:
        for nom2 in range(2):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pk_c = w.get_pubkey_from_path(patchs)
                    pk_uc = PublicKey(pk_c).format(False)
                    bip44_h160_c = CryptoUtils.Hash160(pk_c).hex()
                    bip44_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
                    if inf.debug > 0:
                        print("{} | {} | {} | {} | {}".format(patchs,mnemo,str(seed.hex()),bip44_h160_c,bip44_h160_uc))
                    if (p =="0") and (inf.puzle==True):
                        if bip44_h160_c in inf.list30:
                            print('-------------------------- Found --------------------------',end='\n')
                            bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                            res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+bip_addr_c+' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                            save_rezult(res)
                            if inf.mail == 'yes':
                                send_email(res)
                            counter.increment()
                        inf.count = inf.count + 1
                    if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                        if inf.debug < 1:
                            print("\033[32m \n Init Rescan... \n \033[0m")
                            save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                            if re44(w,mnemo,seed,"m/44'/"+p+"'/",p): counter.increment()
                            print("\033[32m \n Finish Rescan... \n \033[0m")
                    inf.count = inf.count + 2

def nnmnem(mem):
    if inf.mode == 'r':
        mnemonic = ''
        rd=32
        if inf.bit > 64: rd = 64
        if inf.bit < 32: rd = 32
        seed_bytes = os.urandom(rd)
    else:
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic:str = mnemo.generate(strength=inf.bit)
        seed_bytes:bytes = inf.pbkdf2_hmac_sha512_dll(mnemonic)#mnemo.to_seed(mnemonic, passphrase='')
 
    if inf.debug==1:
        mnemo = Mnemonic(mem)
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = inf.pbkdf2_hmac_sha512_dll(mnemonic)#mnemo.to_seed(mnemonic, passphrase='')
        print('Debug SEED : {}'.format(seed_bytes.hex()))
    if inf.debug==2:
        print('Debug Mnemonic : '+mnemonic)
        print('Debug SEED : {}'.format(seed_bytes.hex()))
    return mnemonic, seed_bytes

def re32(in_,mnemo,seed,re_path):
    rez = False
    scan = 0
    for num1 in range(10):
        for t in inf.l32_:
            for num2 in range(2000):
                for t1 in inf.l32_:
                    patchs = re_path+str(num1)+t+"/"+str(num2)+t1
                    pk_c = in_.get_pubkey_from_path(patchs)
                    pk_uc = PublicKey(pk_c).format(False)
                    bip32_h160_c = CryptoUtils.Hash160(pk_c).hex()
                    bip32_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
                    if bip32_h160_c in inf.list30:
                        print('\n-------------------------- Found --------------------------')
                        bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+bip_addr_c+' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
                        rez = True
                    if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                        print('\n-------------------------- Found --------------------------')
                        bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                        bip_addr_uc = P2PKH.ToAddress(pk_uc,net_addr_ver=b"\x00")
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+ bip_addr_c +' | '+bip32_h160_uc +' | '+ bip_addr_uc +' | BIP 32'
                        print(res)
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
                        rez = True
                    print("Scan: {}".format(scan),end='\r')
                    scan +=1
    return rez

def reETH(in_,mnemo,seed,re_path):
    rez = False
    scan=0
    for nom2 in range(10):#accaunt
        for nom3 in range(2):#in/out
            for nom in range(2000):
                patchs = re_path+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                pvk = in_.get_privkey_from_path(patchs)
                pvk_int = int(pvk.hex(),16)
                addr = inf.privatekey_to_ETH_address(pvk_int)
                if addr in inf.bf:
                    print('-------------------------- Found --------------------------',end='\n')
                    res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+addr +' | BIP ETH'
                    print(res)
                    save_rezult(res)
                    if inf.mail == 'yes':
                        send_email(res)
                    rez = True
                print("Scan: {}".format(scan),end='\r')
                scan +=1
    return rez

def re44(in_,mnemo,seed,re_path,code):
    rez = False
    scan=0
    for nom2 in range(10):#accaunt
        for nom3 in range(2):#in/out
            for nom in range(2000):
                patchs = re_path+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                pk_c = in_.get_pubkey_from_path(patchs)
                pk_uc = PublicKey(pk_c).format(False)
                bip44_h160_c = CryptoUtils.Hash160(pk_c).hex()
                bip44_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
                if (code =="0") and (inf.puzle==True):
                    if bip44_h160_c in inf.list30:
                        print('-------------------------- Found --------------------------',end='\n')
                        bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+bip_addr_c+' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
                        rez = True
                if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                    print('-------------------------- Found --------------------------',end='\n')
                    res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ bip44_h160_uc +' | BIP 44'
                    print(res)
                    save_rezult(res)
                    if inf.mail == 'yes':
                        send_email(res)
                    rez = True
                print("Scan: {}".format(scan),end='\r')
                scan +=1
    return rez