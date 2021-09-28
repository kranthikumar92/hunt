# #!/usr/bin/python3
# encoding=utf8
# -*- coding: utf-8 -*-
from funcP import *

def re32(in_,mnemo,seed,re_path):
    for num1 in range(10):
        for t in inf.l32_:
            for num2 in range(10000):
                for t1 in inf.l32_:
                    patchs = re_path+str(num1)+t+"/"+str(num2)+t1
                    pk_c = in_.get_pubkey_from_path(patchs)
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
                    if (bip32_h160_c in inf.bf) or (bip32_h160_uc in inf.bf):
                        print('\n-------------------------- Found --------------------------')
                        bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
                        bip_addr_uc = P2PKH.ToAddress(pk_uc,net_addr_ver=b"\x00")
                        res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip32_h160_c +' | '+ bip_addr_c +' | '+bip32_h160_uc +' | '+ bip_addr_uc +' | BIP 32'
                        save_rezult(res)
                        if inf.mail == 'yes':
                            send_email(res)
    return pass


# def reETH(seed,re_path):
#     w = BIP32.from_seed(seed)
#     for p in inf.leth:
#         for nom2 in range(2):#accaunt
#             for nom3 in range(2):#in/out
#                 for nom in range(50):
#                     patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
#                     pvk = w.get_privkey_from_path(patchs)
#                     pvk_int = int(pvk.hex(),16)
#                     addr = inf.privatekey_to_ETH_address(pvk_int)
#                     if inf.debug > 0:
#                         print("{} | {} | {} | {}".format(patchs,mnemo,seed.hex(),addr))
#                     if addr in inf.bf:
#                         print('-------------------------- Found --------------------------',end='\n')
#                         res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+addr +' | BIP ETH'
#                         print(res)
#                         save_rezult(res)
#                         if inf.mail == 'yes':
#                             send_email(res)
#                         counter.increment()
#                     inf.count = inf.count + 1


# def re44(seed,re_path):
#     w = BIP32.from_seed(seed)
#     for p in inf.l44:
#         for nom2 in range(2):#accaunt
#             for nom3 in range(2):#in/out
#                 for nom in range(20):
#                     patchs = "m/44'/"+p+"'/"+str(nom2)+"'/"+str(nom3)+"/"+str(nom)
#                     pk_c = w.get_pubkey_from_path(patchs)
#                     pk_uc = PublicKey(pk_c).format(False)
#                     bip44_h160_c = CryptoUtils.Hash160(pk_c).hex()
#                     bip44_h160_uc = CryptoUtils.Hash160(pk_uc).hex()
#                     if inf.debug > 0:
#                         print("{} | {} | {} | {} | {}".format(patchs,mnemo,str(seed.hex()),bip44_h160_c,bip44_h160_uc))
#                     if (p =="0") and (inf.puzle==True):
#                         if bip44_h160_c in inf.list30:
#                             print('-------------------------- Found --------------------------',end='\n')
#                             bip_addr_c = P2PKH.ToAddress(pk_c,net_addr_ver=b"\x00")
#                             res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+bip_addr_c+' | BIP 44 / BTC PAZZLE !!!!!!!!!!!!!'
#                             save_rezult(res)
#                             if inf.mail == 'yes':
#                                 send_email(res)
#                             counter.increment()
#                         inf.count = inf.count + 1
#                     if (bip44_h160_c in inf.bf) or (bip44_h160_uc in inf.bf):
#                         print('-------------------------- Found --------------------------',end='\n')
#                         res = patchs+' | '+mnemo+' | '+str(seed.hex())+' | '+bip44_h160_c +' | '+ bip44_h160_uc +' | BIP 44'
#                         print(res)
#                         save_rezult(res)
#                         if inf.mail == 'yes':
#                             send_email(res)
#                         counter.increment()
#                     inf.count = inf.count + 2
