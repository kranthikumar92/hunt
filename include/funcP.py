import sys, smtplib, datetime, socket, secrets
from bloomfilter import BloomFilter
from mnemonic import Mnemonic
from bip_utils.utils import CryptoUtils
from bip_utils import  Bip44, Bip44Coins, Bip49, Bip32, Bip39EntropyGenerator, Bip39MnemonicGenerator, Bip39SeedGenerator,P2SH,P2PKH
from multiprocessing import  Value, Lock


def prn(nem,pk_c,pk_uc,pu_c,pu_uc,h_c_b,h_uc_b,h_c,h_uc,a_c_b,a_uc_b,a_c,a_uc,path,count):
    print('-'*60)
    print('\n* Mnemonic : '+nem)
    print('* Private key compress - {} Public RawCompressed - {}'.format(pk_c,pu_c))
    print('* Private key uncompress- {} Public RawUnCompressed -{}'.format(pk_uc,pu_uc))
    print('* Hash Compress - {} Address Compress -{}'.format(h_c,a_c))
    print('* Hash Uncompress - {} Address UnCompress -{}'.format(h_uc,a_uc))
    print('* Other Hash Compress - {} Other Address Compress -{}'.format(h_c_b,a_c_b))
    print('* Other Hash Uncompress - {} Other Address UnCompress -{}'.format(h_uc_b,a_uc_b))
    print('* Path or cyrency - {}'.format(path))
    print('* Found - {}'.format(count.value()),end='\n')

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

def load_BF(dir,bf_file):
    BF_:BloomFilter
    try:
        fp = open(dir+'/'+bf_file, 'rb')
    except FileNotFoundError:
        print('\n'+'File: '+ bf_file + ' not found.')
        sys.exit()
    else:
        BF_ = BloomFilter.load(fp)
        print('* Bloom Filter '+bf_file+' Loaded.')
    return BF_

def load_btc30(dir,file):
    BTC30_:list
    try:
        fp = open(dir+'/'+file, 'r')
    except FileNotFoundError:
        print('\n'+'File: btc30.h160 not found.')
        sys.exit()
    else:
        lines = fp.readlines()
        BTC30_ = [line.rstrip('\n') for line in lines]
        fp.close()
        print('* File address pazzle BTC~30 Loaded.')
    return BTC30_

def send_email(i,e,text):
    subject = ''
    current_date = datetime.datetime.now()
    i.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = str(i.dt_now) + ' | ' + text
    subject = e.subject + ' description -> ' + e.des_mail
    BODY:str = '\r\n'.join(('From: %s' % e.from_addr, 'To: %s' % e.to_addr, 'Subject: %s' % subject, '', text)).encode('utf-8')
    try:
        server = smtplib.SMTP(e.host,e.port)
    except (smtplib.SMTPAuthenticationError) or (OSError,ConnectionRefusedError):
        print("\n[*] could not connect to the mail server")
        i.mail_nom += 1
        if i.mail_nom >= 3:
            i.mail = 'no'
    except ConnectionRefusedError:
        print("\n[*] could not connect to the mail server")
        i.mail_nom += 1
        if i.mail_nom >= 3:
            i.mail = 'no'
    else:
        server.login(e.from_addr, e.password)
        try:
            server.sendmail(e.from_addr, e.to_addr, BODY)
        except UnicodeError:
            print('\n[*] Error Encode UTF-8')
        else:
            server.quit()

def save_rezult(i,text:str):
    current_date = datetime.datetime.now()
    i.dt_now = current_date.strftime('%m/%d/%y %H:%M:%S')
    text = i.dt_now+' | '+ text
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

def send_stat(s, i, uid,des,bip,process_count_work,speed,total,found):
    b=b','
    name = des.encode('utf-8')
    mode = str(bip).encode('utf-8')
    thread = str(process_count_work).encode('utf-8')
    speed = str(speed).encode('utf-8')
    total = str(total).encode('utf-8')
    found = str(found).encode('utf-8')
    time_t = datetime.datetime.now()
    time_b = time_t.strftime("%y/%m/%d %H:%M").encode('utf-8')
    ver = i.version
    work = b'Worker online'
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_sock.connect((s.server, s.port))
        client_sock.sendall(uid+b+name+b+mode+b+thread+b+speed+b+total+b+found+b+time_b+b+work)
    except (UnboundLocalError, ConnectionResetError, ConnectionError) as msg:
        print("\nSocket creation error. Send Statictic Stop!")
        i.sock_nom += 1
        if i.sock_nom >= 3:
            i.socket = 'no'
    else:
        data = client_sock.recv(1024)
        client_sock.close()
        return data

def b32(i, e, mnemo, seed, counter):
    for path in i.l32:
        for num in range(20):
            bip32_ctx = Bip32.FromSeedAndPath(seed, path+'/'+str(num))
            bip32_h160_c = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
            bip32_h160_uc = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
            if i.debug > 0:
                pk_c = bip32_ctx.PrivateKey().ToWif()
                pk_uc = bip32_ctx.PrivateKey().ToWif(compr_pub_key = False)
                pu_c = bip32_ctx.PublicKey().RawCompressed().ToHex()
                pu_uc = bip32_ctx.PublicKey().RawUncompressed().ToHex()
                h_c = bip32_h160_c
                h_uc = bip32_h160_uc
                a_c = P2PKH.ToAddress(bip32_ctx.PublicKey().RawCompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                a_uc = P2PKH.ToAddress(bip32_ctx.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                path_ = path+'/'+str(num)
                prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,path_,counter)
            if any(element in bip32_h160_c for element in i.list30) or any(element in bip32_h160_uc for element in i.list30):
                print('\n-------------------------- Find --------------------------')
                bip32_PK_c = bip32_ctx.PrivateKey().ToWif()
                bip32_PK_uc = bip32_ctx.PrivateKey().ToWif(compr_pub_key = False)
                bip_addr_c = P2PKH.ToAddress(bip32_ctx.PublicKey().RawCompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr_uc = P2PKH.ToAddress(bip32_ctx.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_PK_c+' | '+bip32_h160_c +' | '+bip_addr_c +' | '+ bip32_PK_uc+' | '+bip32_h160_uc +' | '+ bip_addr_uc +' | '+ mnemo +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                prn(mnemo,bip32_PK_c,bip32_PK_uc,None,None,None,None,None,None,None,None,bip_addr_c,bip_addr_uc,path+'/'+str(num),counter)
                save_rezult(i, res)
                if i.mail == 'yes':
                    send_email(i,e,res)
                counter.increment()
            if (bip32_h160_c in i.bf) or (bip32_h160_uc in i.bf):
                print('\n-------------------------- Find --------------------------')
                bip32_PK_c = bip32_ctx.PrivateKey().ToWif()
                bip32_PK_uc = bip32_ctx.PrivateKey().ToWif(compr_pub_key = False)
                bip_addr_c = P2PKH.ToAddress(bip32_ctx.PublicKey().RawCompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                bip_addr_uc = P2PKH.ToAddress(bip32_ctx.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=b"\x00")#public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                res = bip32_PK_c+' | '+bip32_h160_c +' | '+bip_addr_c +' | '+ bip32_PK_uc+' | '+bip32_h160_uc +' | '+ bip_addr_uc +' | '+ mnemo +' | BIP 32 / BTC'
                prn(mnemo,bip32_PK_c,bip32_PK_uc,None,None,None,None,None,None,None,None,bip_addr_c,bip_addr_uc,path+'/'+str(num),counter)
                save_rezult(i, res)
                if i.mail == 'yes':
                    send_email(i,e,res)
                counter.increment()
            i.count = i.count + 2

def bETH(i, e, mnemo, seed, counter):
    for cyr in i.leth:
        bip_obj_mst_e = Bip44.FromSeed(seed,cyr)
        for nom2 in range(2):
            bip_obj_acc_e = bip_obj_mst_e.Purpose().Coin().Account(nom2)
            for nom3 in i.l44__:
                bip_obj_chain_e = bip_obj_acc_e.Change(nom3)
                for nom in range(10):
                    bip_obj_addr = bip_obj_chain_e.AddressIndex(nom)
                    bip_addr:str = bip_obj_addr.PublicKey().ToAddress()
                    if i.debug > 0:
                        pk_c = bip_obj_addr.PrivateKey().Raw().ToHex()
                        pu_c = bip_obj_addr.PublicKey().RawCompressed().ToHex()
                        prn(mnemo,pk_c,None,pu_c,None,None, None,None,None,None,None, bip_addr,None,str(cyr)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                    if bip_addr in i.bf:
                        print('============== Find =================')
                        bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                        res:str = bip44_PK + ' | ' + bip_addr +' | ' + mnemo + ' | BIP 44 / '+str(cyr)
                        prn(mnemo,pk_c,None,pu_c,None,None, None,None,None,None,None, bip_addr,None,str(cyr)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                        save_rezult(i, res)
                        if i.mail == 'yes':
                            send_email(i,e,res)
                        counter.increment()
                    i.count = i.count + 1

def b44(i, e, mnemo, seed, counter):
    no = 0
    for p in i.l44:
        net_code = i.l44_[no]
        bip_obj_mst_44 = Bip44.FromSeed(seed, p)
        for nom2 in range(4):
            bip_obj_acc_44 = bip_obj_mst_44.Purpose().Coin().Account(nom2)
            for nom3 in i.l44__:
                bip_obj_chain_44 = bip_obj_acc_44.Change(nom3)
                for nom in range(20):
                    bip_obj_addr = bip_obj_chain_44.AddressIndex(nom)
                    bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
                    bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
                    if i.debug > 0:
                        pk_c = bip_obj_addr.PrivateKey().ToWif()
                        pk_uc = bip_obj_addr.PrivateKey().ToWif(compr_pub_key = False)
                        pu_c = bip_obj_addr.PublicKey().RawCompressed().ToHex()
                        pu_uc = bip_obj_addr.PublicKey().RawUncompressed().ToHex()
                        h_c = bip44_hc
                        h_uc = bip44_huc
                        a_c = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawCompressed().ToBytes(),net_addr_ver=net_code)
                        a_uc = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=net_code)
                        prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,str(p)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                        print(bip_obj_addr.PublicKey().ToAddress())
                    if p==Bip44Coins.BITCOIN:
                        if any(element in bip44_hc for element in i.list30):
                            print('-------------------------- Find --------------------------',end='\n')
                            bip44_PK_c = bip_obj_addr.PrivateKey().ToWif()
                            bip44_PK_uc = bip_obj_addr.PrivateKey().ToWif(compr_pub_key = False)
                            bip_addr_c = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawCompressed().ToBytes(),net_addr_ver=net_code)
                            bip_addr_uc = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=net_code)
                            res = bip44_PK_c +' | '+ bip_addr_c +' | '+ bip44_PK_uc +' | '+ bip_addr_uc + ' | '+ mnemo +' | '+ ' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                            prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,str(p)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                            save_rezult(i,res)
                            if i.mail == 'yes':
                                send_email(i,e,res)
                            counter.increment()
                        i.count = i.count + 1
                         
                    if (bip44_hc in i.bf) or (bip44_huc in i.bf):
                        print('-------------------------- Find --------------------------',end='\n')
                        bip44_PK_c = bip_obj_addr.PrivateKey().ToWif()
                        bip44_PK_uc = bip_obj_addr.PrivateKey().ToWif(compr_pub_key = False)
                        bip_addr_c = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawCompressed().ToBytes(),net_addr_ver=net_code)
                        bip_addr_uc = P2PKH.ToAddress(bip_obj_addr.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=net_code)
                        res = bip44_PK_c +' | '+ bip_addr_c +' | '+ bip44_PK_uc +' | '+ bip_addr_uc + ' | '+ mnemo +' | '+ ' | BIP 44 /'+str(p)
                        prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,str(p)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                        save_rezult(i,res)
                        if i.mail == 'yes':
                            send_email(i, e, res)
                        counter.increment()
                    i.count = i.count + 2
        no += 1

def b49(i, e, mnemo, seed, counter):
    no = 0
    for p in i.l49:
        net_code = i.l49_[no]
        bip_obj_mst_44 = Bip49.FromSeed(seed, p)
        for nom2 in range(2):
            bip_obj_acc_44 = bip_obj_mst_44.Purpose().Coin().Account(nom2)
            for nom3 in i.l44__:
                bip_obj_chain_44 = bip_obj_acc_44.Change(nom3)
                for nom in range(20):
                    bip_obj_addr = bip_obj_chain_44.AddressIndex(nom)
                    bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
                    bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
                    if i.debug > 0:
                        pk_c = bip_obj_addr.PrivateKey().ToWif()
                        pk_uc = bip_obj_addr.PrivateKey().ToWif(compr_pub_key = False)
                        pu_c = bip_obj_addr.PublicKey().RawCompressed().ToHex()
                        pu_uc = bip_obj_addr.PublicKey().RawUncompressed().ToHex()
                        h_c = bip44_hc
                        h_uc = bip44_huc
                        a_c = P2SH.ToAddress(bip_obj_addr.PublicKey().RawCompressed().ToBytes(),net_addr_ver=net_code)
                        a_uc = P2SH.ToAddress(bip_obj_addr.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=net_code)
                        prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,str(p)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                        print(bip_obj_addr.PublicKey().ToAddress())
                    if (bip44_huc in i.bf) or (bip44_huc in i.bf):
                        print('-------------------------- Find --------------------------',end='\n')
                        bip44_PK_c = bip_obj_addr.PrivateKey().ToWif()
                        bip44_PK_uc = bip_obj_addr.PrivateKey().ToWif(compr_pub_key = False)
                        bip_addr_c = P2SH.ToAddress(bip_obj_addr.PublicKey().RawCompressed().ToBytes(),net_addr_ver=net_code)
                        bip_addr_uc = P2SH.ToAddress(bip_obj_addr.PublicKey().RawUncompressed().ToBytes(),net_addr_ver=net_code)
                        res = bip44_PK_c +' | '+ bip_addr_c +' | '+ bip44_PK_uc +' | '+ bip_addr_uc + ' | '+ mnemo +' | '+  +' | BIP 44 /'+str(p)
                        prn(mnemo,pk_c,pk_uc,pu_c,pu_uc,None,None,h_c,h_uc,None,None,a_c,a_uc,str(p)+' - account-'+str(nom2)+'/Change '+str(nom3) +'/'+ str(nom),counter)
                        save_rezult(i,res)
                        if i.mail == 'yes':
                            send_email(i, e, res)
                        counter.increment()
                    i.count = i.count + 2
        no += 1

def nnmnem(i, mem):
    if i.mode == 'r':
        seed_bytes:bytes = secrets.token_bytes(64)
        mnemonic = ''
    elif i.mode == 'e':
        entropy_bytes = Bip39EntropyGenerator(i.bit_entropy).Generate()
        mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_bytes)
        seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    else:
        mnemo = Mnemonic(mem)
        mnemonic:str = mnemo.generate(i.words)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')

    if i.debug==1:
        mnemo = Mnemonic(mem)
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        print('Debug SEED : '+ str(seed_bytes))
    if i.debug==2:
        print('Debug Mnemonic : '+mnemonic)
        print('Debug SEED : '+ str(seed_bytes))
    return mnemonic, seed_bytes
