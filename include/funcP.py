import hashlib,codecs, sys, smtplib, datetime, socket, secrets
from bloomfilter import BloomFilter
from mnemonic import Mnemonic
from bip_utils.utils import CryptoUtils
from bip_utils import  Bip44, Bip44Coins, Bip44Changes, Bip49, Bip32
from multiprocessing import  Value, Lock#Process,

def dbg(nem, pc,puc,hc,huc,p,ac,auc,cc):
    print('\n* Debug Mnemonic : '+nem)
    print('* Public RawCompressed - {}'.format(pc))
    print('* Public RawUnCompressed - {}'.format(puc))
    print('* Hash Compress - {}'.format(hc))
    print('* Hash Uncompress - {}'.format(huc))
    print('* Path or cyrency - {}'.format(p))
    print('* Address Compress - {}'.format(ac))
    print('* Address UnCompress - {}'.format(auc),end='\n')
    print('\n* Found - {}'.format(cc.value()))

def prn(hc,ac,huc,auc,nem,pk,p):
    print('\n* Debug Mnemonic : '+nem)
    print('* Private key - {}'.format(pk))
    print('* Hash Compress - {}'.format(hc))
    print('* Hash Uncompress - {}'.format(huc))
    print('* Path - {}'.format(p))
    print('* Address Compress - {}'.format(ac))
    print('* Address UnCompress - {}'.format(auc),end='\n')

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

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros and convert hex to decimal
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

def public_to_address(public_key,net_byte:bytes):
    public_key_bytes = codecs.decode(public_key, 'hex')
    # Run SHA256 for the public key
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    # Run ripemd160 for the SHA256
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    # Add network byte
    network_byte = net_byte#b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    # Double SHA256 to get checksum
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    # Concatenate public key and checksum to get the address
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    wallet = base58(address_hex)
    return wallet

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
    except (smtplib.SMTPAuthenticationError) or (OSError):
        print("\n[*] could not connect to the mail server")
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
    work = b'Worker online'
    
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_sock.connect((s.server, s.port))
        client_sock.sendall(uid+b+name+b+mode+b+thread+b+speed+b+total+b+found+b+time_b+b+work)
    except (UnboundLocalError, ConnectionError) as msg:
        print("\nSocket creation error. Send Statictic Stop!")
        i.socket = 'no'
    else:
        data = client_sock.recv(1024)
        client_sock.close()
        return data

def b32(i, e, mnemo, seed, counter):
    for path in i.l32:
        for path_ in i.l32_:
            for num in range(20):
                bip32_ctx = Bip32.FromSeedAndPath(seed, path + str(num)+path_)
                bip32_h160_1 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawCompressed().ToBytes()).hex()
                bip32_h160_2 = CryptoUtils.Hash160(bip32_ctx.PublicKey().RawUncompressed().ToBytes()).hex()
                if i.debug > 0:
                    dbg(mnemo, bip32_ctx.PublicKey().RawCompressed().ToHex(), bip32_ctx.PublicKey().RawUncompressed().ToHex(), 
                        bip32_h160_1, bip32_h160_2, path+str(num)+path_,
                        public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00'),public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00'),counter)
                if any(element in bip32_h160_1 for element in i.list30) or any(element in bip32_h160_2 for element in i.list30):
                    print('\n-------------------------- Find --------------------------')
                    bip32_PK = bip32_ctx.PrivateKey().ToWif()
                    bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                    bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                    res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | '+ mnemo +' | '+ bip32_PK +' | BIP 32 / BTC PAZZLE !!!!!!!!!!!!!'
                    prn(bip32_h160_1,bip_addr,bip32_h160_2,bip_addr2,mnemo,bip32_PK,path+str(num)+path_)
                    save_rezult(i, res)
                    if i.mail == 'yes':
                        send_email(i,e,res)
                    counter.increment()
                if (bip32_h160_1 in i.bf) or (bip32_h160_2 in i.bf):
                    print('\n-------------------------- Find --------------------------')
                    bip32_PK = bip32_ctx.PrivateKey().ToWif()
                    bip_addr = public_to_address(bip32_ctx.PublicKey().RawCompressed().ToHex(),b'00')
                    bip_addr2 = public_to_address(bip32_ctx.PublicKey().RawUncompressed().ToHex(),b'00')
                    res = bip32_h160_1 +' | '+bip_addr +' | '+ bip32_h160_2 +' | '+ bip_addr2 +' | '+ mnemo +' | '+ bip32_PK +' | BIP 32 / BTC'
                    prn(bip32_h160_1,bip_addr,bip32_h160_2,bip_addr2,mnemo,bip32_PK,path+str(num)+path_)
                    save_rezult(i, res)
                    if i.mail == 'yes':
                        send_email(i,e,res)
                    counter.increment()
                i.count = i.count + 2

def bETH(i, e, mnemo, seed, counter):
    bip_obj_mst = Bip44.FromSeed(seed,Bip44Coins.ETHEREUM)
    for nom2 in range(10):
        bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(nom2)
        for nom3 in i.l44__:
            bip_obj_chain = bip_obj_acc.Change(nom3)
            for nom in range(20):
                bip_obj_addr = bip_obj_chain.AddressIndex(nom)
                bip_addr:str = bip_obj_addr.PublicKey().ToAddress()
                if i.debug > 0:
                    dbg(mnemo, bip_obj_addr.PublicKey().RawCompressed().ToHex(), '', 
                        '', '', "ETHEREUM - " + str(nom), bip_addr,'',counter)
                if bip_addr in i.bf:
                    print('============== Find =================')
                    bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                    res:str = bip_addr + ' | ' + mnemo + ' | ' + bip44_PK +' | BIP 44 / ETHEREUM'
                    prn('',bip_addr,'','',mnemo,bip44_PK,"ETHEREUM - " + str(nom))
                    save_rezult(i, res)
                    if i.mail == 'yes':
                        send_email(i,e,res)
                    counter.increment()
                i.count = i.count + 1

def b44(i, e, mnemo, seed, counter):
    no = 0
    for p in i.l44:
        net_code = i.l44_[no]
        bip_obj_mst = Bip44.FromSeed(seed, p)
        for nom2 in range(5):
            bip_obj_acc = bip_obj_mst.Purpose().Coin().Account(nom2)
            for nom3 in i.l44__:
                bip_obj_chain = bip_obj_acc.Change(nom3)
                for nom in range(20):
                    bip_obj_addr = bip_obj_chain.AddressIndex(nom)
                    bip44_hc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawCompressed().ToBytes()).hex()
                    bip44_huc = CryptoUtils.Hash160(bip_obj_addr.PublicKey().RawUncompressed().ToBytes()).hex()
                    if i.debug > 0:
                        dbg(mnemo, bip_obj_addr.PublicKey().RawCompressed().ToHex(), bip_obj_addr.PublicKey().RawUncompressed().ToHex(), 
                            bip44_hc, bip44_huc, str(p) +" - " + str(nom),
                            public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),net_code), public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),net_code),counter)
                    if p==Bip44Coins.BITCOIN:
                        if any(element in bip44_hc for element in i.list30) or any(element in bip44_huc for element in i.list30):
                            print('-------------------------- Find --------------------------',end='\n')
                            bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                            bip_addr = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),net_code)
                            bip_addr2 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),net_code)
                            res =bip44_hc +' | '+ bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 + ' | '+ mnemo +' | '+ bip44_PK +' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
                            prn(bip44_hc,bip_addr,bip44_huc,bip_addr2,mnemo,bip44_PK,str(p) +" - " + str(nom))
                            save_rezult(i,res)
                            if i.mail == 'yes':
                                send_email(i,e,res)
                            counter.increment()
                    if (bip44_hc in i.bf) or (bip44_huc in i.bf):
                        print('-------------------------- Find --------------------------',end='\n')
                        bip44_PK = bip_obj_addr.PrivateKey().ToWif()
                        bip_addr = public_to_address(bip_obj_addr.PublicKey().RawCompressed().ToHex(),net_code)
                        bip_addr2 = public_to_address(bip_obj_addr.PublicKey().RawUncompressed().ToHex(),net_code)
                        res =bip44_hc +' | '+ bip_addr +' | '+ bip44_huc +' | '+ bip_addr2 + ' | '+ mnemo +' | '+ bip44_PK +' | '+str(p) +" - " + str(nom)
                        prn(bip44_hc,bip_addr,bip44_huc,bip_addr2,mnemo,bip44_PK,str(p) +" - " + str(nom))
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
        #print(seed_bytes.hex())
    else:
        mnemo = Mnemonic(mem)
        mnemonic:str = mnemo.generate(i.words)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        #print(seed_bytes.hex())
    if i.debug==1:
        mnemonic = 'world evolve cry outer garden common differ jump few diet cliff lumber'
        print('Debug Mnemonic : '+mnemonic)
        seed_bytes:bytes = mnemo.to_seed(mnemonic, passphrase='')
        print('Debug SEED : '+ str(seed_bytes))
    if i.debug==2:
        print('Debug Mnemonic : '+mnemonic)
        print('Debug SEED : '+ str(seed_bytes))
    return mnemonic, seed_bytes
