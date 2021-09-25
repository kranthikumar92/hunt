from consts import *
import sys, smtplib, datetime, socket, os
from mnemonic import Mnemonic
from bip_utils.utils import CryptoUtils
from bip_utils import  P2SH,P2PKH,EthAddr
from multiprocessing import  Value, Lock
from bip32 import BIP32 as BIP44
from bip32 import BIP32
from coincurve import PublicKey

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
        print('\n'+'File: '+ load + ' not found.')
        sys.exit()
    else:
        inf.bf = BloomFilter.load(fp)
        print('* Bloom Filter Loaded...')

def load_btc30(load):
    try:
        fp = open(load, 'r')
    except FileNotFoundError:
        print('\n'+'File: '+load+' not found.')
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
        print("\n[*] could not connect to the mail server")
        inf.mail_nom += 1
        if inf.mail_nom >= 3:
            inf.mail = 'no'
    except ConnectionRefusedError:
        print("\n[*] could not connect to the mail server")
        inf.mail_nom += 1
        if inf.mail_nom >= 3:
            inf.mail = 'no'
    else:
        server.login(email.from_addr, email.password)
        try:
            server.sendmail(email.from_addr, email.to_addr, BODY)
        except UnicodeError:
            print('\n[*] Error Encode UTF-8')
        else:
            server.quit()

def save_rezult(text:str):
    current_date = datetime.datetime.now()
    inf.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = inf.dt_now+' | '+ text
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
        print("\nSocket creation error. Send Statictic Stop!")
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
        for num1 in range(5):
            for t in inf.l32_:
                for num2 in range(20):
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
                            print('\n-------------------------- Find --------------------------')
                            bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                            res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+bip_addr_c+' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                            save_rezult(res)
                            if inf.mail == 'yes':
                                send_email(res)
                            counter.increment()
                        inf.count = inf.count + 1
                        if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                            print('\n-------------------------- Find --------------------------')
                            bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                            bip_addr_uc = P2PKH.ToAddress(pk_uc,net_addr_ver=b"\x00")
                            res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+ bip_addr_c +' | '+bip32_h160_uc +' | '+ bip_addr_uc +' | BIP 32'
                            save_rezult(res)
                            if inf.mail == 'yes':
                                send_email(res)
                            counter.increment()
                        inf.count = inf.count + 2

def bETH(mnemo, seed, counter):
    w = BIP44.from_seed(seed)
    for p in inf.leth:
        for nom2 in range(5):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(20):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pk_c = w.get_pubkey_from_path(patchs)
                    pk_uc = PublicKey(pk_c).format(False)
                    addr = EthAddr.ToAddress(pk_uc[1:])
                    if inf.debug > 0:
                        print("{} | {} | {} | {}".format(patchs,mnemo,seed.hex(),addr))
                    if addr in inf.bf:
                        print('-------------------------- Find --------------------------',end='\n')
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+addr +' | BIP 44 ETH'
                        print(res)
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
                        counter.increment()
                    inf.count = inf.count + 1

def b44(mnemo, seed, counter):
    w = BIP44.from_seed(seed)
    for p in inf.l44:
        for nom2 in range(4):#accaunt
            for nom3 in range(2):#in/out
                for nom in range(10):
                    patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
                    pk_c = w.get_pubkey_from_path(patchs)
                    pk_uc = PublicKey(pk_c).format(False)
                    bip44_h160_c = CryptoUtils.Hash160(pk_c).hex()
                    bip44_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
                    if inf.debug > 0:
                        print("{} | {} | {} | {} | {}".format(patchs,mnemo,str(seed.hex()),bip44_h160_c,bip44_h160_uc))
                    if (p =="0") and (inf.puzle==True):
                        if bip44_h160_c in inf.list30:
                            print('-------------------------- Find --------------------------',end='\n')
                            bip_addr_c = P2PKH.ToAddress(bip44_h160_c,net_addr_ver=b"\x00")
                            res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+bip_addr_c+' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                            save_rezult(res)
                            if inf.mail == 'yes':
                                send_email(res)
                            counter.increment()
                        inf.count = inf.count + 1
                    if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
                        print('-------------------------- Find --------------------------',end='\n')
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ bip44_h160_uc +' | BIP 44'
                        print(res)
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
                        counter.increment()
                    inf.count = inf.count + 2


def nnmnem(mem):
    if inf.mode == 'r':
        mnemonic = ''
        seed_bytes = os.urandom(inf.bit)
    else:
        mnemo:Mnemonic = Mnemonic(mem)
        mnemonic:str = mnemo.generate(strength=inf.bit)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')

    if inf.debug==1:
        mnemo = Mnemonic(mem)
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        print('Debug SEED : '+ str(seed_bytes))
    if inf.debug==2:
        print('Debug Mnemonic : '+mnemonic)
        print('Debug SEED : '+ str(seed_bytes))
    return mnemonic, seed_bytes
