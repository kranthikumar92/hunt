# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
from consts import *

def load_BF(load, tr1):
    try:
        fp = open(load, 'rb')
    except FileNotFoundError:
        print('\033[1;31m \n'+'File: '+ load + ' not found. \033[0m')
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
        try:
            server.login(email.from_addr, email.password)
        except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
            print("\033[1;31m \n[*] could not connect to the mail server \033[0m")
            inf.mail_nom += 1
            if inf.mail_nom >= 3:
                inf.mail = 'no'
        else:
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
                        bip32_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int).hex()
                        bip32_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int).hex()
                        if inf.debug > 0:
                            h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                            h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                            addr_c = secp256k1_lib.hash_to_address(0,True,h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0,False,h160_uc)
                            print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip32_h160_c,addr_c,bip32_h160_uc,addr_uc))
                        if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                            if inf.debug > 0:
                                fdbg = open('dbg32.txt','a')
                                fdbg.write("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip32_h160_c,addr_c,bip32_h160_uc,addr_uc))
                                fdbg.close()
                            if inf.debug < 1:
                                print("\033[32m \n Init Rescan... \n \033[0m")
                                save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                                if re32(bip32,mnemo,seed,path): counter.increment()
                                print("\033[32m \n Finish Rescan... \n \033[0m")
                        inf.count = inf.count + 2

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
                        print("{} | {} | {} | {}".format(patchs,mnemo,seed.hex(),addr))
                    if addr in inf.bf:
                        if inf.debug >0:
                            fdbg = open('dbgETH.txt','a')
                            fdbg.write("{} | {} | {} | {}".format(patchs,mnemo,seed.hex(),addr))
                            fdbg.close()
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
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int).hex()
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int).hex()
                    if inf.debug > 0 :
                        if p=='0':
                            h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                            h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                            addr_c = secp256k1_lib.hash_to_address(0,True,h160_c)
                            addr_uc = secp256k1_lib.hash_to_address(0,False,h160_uc)
                            print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                        else:
                            print("{} | {} | {} | {} | {}".format(patchs,mnemo,str(seed.hex()),bip44_h160_c,bip44_h160_uc))
                    if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                        if inf.debug >0:
                            if p=='0':
                                fdbg = open('dbg44_btc.txt','a')
                                fdbg.write("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                                fdbg.close()
                            else:
                                fdbg = open('dbg44_other.txt','a')
                                fdbg.write("{} | {} | {} | {} | {}".format(patchs,mnemo,str(seed.hex()),bip44_h160_c,bip44_h160_uc))
                                fdbg.close()
                        if inf.debug < 1:
                            print("\033[32m \n Init Rescan... \n \033[0m")
                            save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                            if re44(w,mnemo,seed,"m/44'/"+p+"'/",p): counter.increment()
                            print("\033[32m \n Finish Rescan... \n \033[0m")
                    inf.count = inf.count + 2

def bBTC(mnemo, seed, counter):
    pur = 0
    w = BIP32.from_seed(seed)
    for bip_ in inf.lbtc:
        if bip_ == "44": pur = 0
        else: pur = 1
        for nom2 in range(2):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/"+bip_+"'/0'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pvk = w.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip44_h160_c = secp256k1_lib.privatekey_to_h160(pur, True, pvk_int).hex()
                    bip44_h160_uc = secp256k1_lib.privatekey_to_h160(pur, False, pvk_int).hex()
                    if inf.debug > 0 :
                        h160_c = secp256k1_lib.privatekey_to_h160(pur, True, pvk_int)
                        h160_uc = secp256k1_lib.privatekey_to_h160(pur, False, pvk_int)
                        addr_c = secp256k1_lib.hash_to_address(pur,True,h160_c)
                        addr_uc = secp256k1_lib.hash_to_address(pur,False,h160_uc)
                        print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                    if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                        if inf.debug >0:
                            fdbg = open('dbgBTC.txt','a')
                            fdbg.write("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                            fdbg.close()
                        if inf.debug < 1:
                            print("\033[32m \n Init Rescan... \n \033[0m")
                            save_rezult("Init Rescan |"+mnemo+"|"+str(seed.hex()))
                            if reBTC(w,mnemo,seed,"m/"+bip_+"'/0'/",bip_): counter.increment()
                            print("\033[32m \n Finish Rescan... \n \033[0m")
                    inf.count = inf.count + 2

def re32(in_,mnemo,seed,re_path):
    rez = False
    scan = 0
    for num1 in range(50):
        for t in inf.l32_:
            for num2 in range(2000):
                for t1 in inf.l32_:
                    patchs = re_path+str(num1)+t+"/"+str(num2)+t1
                    pvk = in_.get_privkey_from_path(patchs)
                    pvk_int = int(pvk.hex(),16)
                    bip32_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int).hex()
                    bip32_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int).hex()
                    if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                        print('\n-------------------------- Found --------------------------')
                        h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                        h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                        bip_addr_c = secp256k1_lib.hash_to_address(0,True,h160_c)
                        bip_addr_uc = secp256k1_lib.hash_to_address(0,False,h160_uc)
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
    for nom2 in range(50):#accaunt
        for nom3 in range(2):#in/out
            for nom in range(2000):
                patchs = re_path+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                pvk = in_.get_privkey_from_path(patchs)
                pvk_int = int(pvk.hex(),16)
                addr = secp256k1_lib.privatekey_to_ETH_address(pvk_int)
                if addr in inf.bf:
                    print('-------------------------- Found --------------------------',end='\n')
                    res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+addr +' | BIP ETH/ETC'
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
    for nom2 in range(50):#accaunt
        for nom3 in range(2):#in/out
            for nom in range(2000):
                patchs = re_path+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                pvk = in_.get_privkey_from_path(patchs)
                pvk_int = int(pvk.hex(),16)
                bip44_h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int).hex()
                bip44_h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int).hex()
                if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                    print('-------------------------- Found --------------------------',end='\n')
                    if code=='0':
                        h160_c = secp256k1_lib.privatekey_to_h160(0, True, pvk_int)
                        h160_uc = secp256k1_lib.privatekey_to_h160(0, False, pvk_int)
                        addr_c = secp256k1_lib.hash_to_address(0,True,h160_c)
                        addr_uc = secp256k1_lib.hash_to_address(0,False,h160_uc)
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ addr_c +' | '+bip44_h160_uc +' | '+ addr_uc +' | BIP 44'
                        print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                    else:
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ bip44_h160_uc +' | BIP 44'
                    print(res)
                    save_rezult(res)
                    if inf.mail == 'yes':
                        send_email(res)
                    rez = True
                print("Scan: {}".format(scan),end='\r')
                scan +=1
    return rez

def reBTC(in_,mnemo,seed,re_path,pure):
    rez = False
    scan=0
    for nom2 in range(10):#accaunt
        for nom3 in range(2):#in/out
            for nom in range(2000):
                patchs = re_path+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                pvk = in_.get_privkey_from_path(patchs)
                pvk_int = int(pvk.hex(),16)
                bip44_h160_c = secp256k1_lib.privatekey_to_h160(pure, True, pvk_int).hex()
                bip44_h160_uc = secp256k1_lib.privatekey_to_h160(pure, False, pvk_int).hex()
                if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                    print('-------------------------- Found --------------------------',end='\n')
                    h160_c = secp256k1_lib.privatekey_to_h160(pure, True, pvk_int)
                    h160_uc = secp256k1_lib.privatekey_to_h160(pure, False, pvk_int)
                    addr_c = secp256k1_lib.hash_to_address(pure,True,h160_c)
                    addr_uc = secp256k1_lib.hash_to_address(pure,False,h160_uc)
                    res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ addr_c +' | '+bip44_h160_uc +' | '+ addr_uc +' | BIP 44'
                    print("{} | {} | {} | {} | {} | {} | {}".format(patchs,mnemo,seed.hex(),bip44_h160_c,addr_c,bip44_h160_uc,addr_uc))
                    print(res)
                    save_rezult(res)
                    if inf.mail == 'yes':
                        send_email(res)
                    rez = True
                print("Scan: {}".format(scan),end='\r')
                scan +=1
    return rez


def nnmnem(mem):
    if inf.mode == 'r1':
        mnemonic = ''
        rd=32
        if inf.bit > 64: rd = 64
        if inf.bit < 32: rd = 32
        seed_bytes = os.urandom(rd)
    elif inf.mode =='r2':
        mnemo:Mnemonic = Mnemonic('english')
        mnemonic = ''
        f = open('wl/english.txt','r')
        list_en = [line.strip() for line in f]
        for wi in (range(12)):
            r1 = random.randint(0, 2047)
            if wi == 11:
                mnemonic = mnemonic + list_en[r1]
            else:
                mnemonic = mnemonic + list_en[r1]+' '
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')

    else:
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic:str = mnemo.generate(strength=inf.bit)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
 
    if inf.debug==1:
        mnemo = Mnemonic(mem)
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='mnemonic')
        print('Debug SEED : {}'.format(seed_bytes.hex()))
    if inf.debug==2:
        print('Debug Mnemonic : '+mnemonic)
        print('Debug SEED : {}'.format(seed_bytes.hex()))
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