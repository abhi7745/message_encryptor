
# from cryptography import fernet
# import cryptography
from typing import BinaryIO
from django.shortcuts import render

# importing password encryptor
from django.contrib.auth.hashers import make_password, check_password, mask_hash

from cryptography.fernet import Fernet #for text encryption And decryption

import base64,hashlib

# from base64 import urlsafe_b64decode
from struct import unpack

from base64 import urlsafe_b64decode
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend


# Create your views here.


def index(request):
    return render(request,'index.html',{})


def encrypt2(request):
    if request.method=='POST':
        text1=request.POST.get('text1')
        # psd_e=request.POST.get('psd_e')
        print(text1)
        # print(psd_e,type(psd_e))

         # creating key strings
        keys = 'abcdefghijklmnopqrstuvwxyz1234567890 !'
        # auto generating the vaules of strings
        # value will be generted by taking last to first
        # concatinated with the rest of the string
        values = keys[-1] + keys[0:-1]
        print(keys)
        print(values)

        # creating two dictionaries
        encrytDict = dict(zip(keys, values))
        decryptDict = dict(zip(values, keys))
        print(encrytDict)
        print(decryptDict)

        newMessage = ''.join([encrytDict[letter] for letter in text1.lower()])
        print(newMessage)

        


    return render(request,'index.html',{'E_msg':newMessage,'text1':text1})


def decrypt2(request):
    if request.method=='POST':
        text2=request.POST.get('text2')
        # psd_d=request.POST.get('psd_d')
        print(text2)
        # print(psd_d)

         # creating key strings
        keys = 'abcdefghijklmnopqrstuvwxyz1234567890 !'
        # auto generating the vaules of strings
        # value will be generted by taking last to first
        # concatinated with the rest of the string
        values = keys[-1] + keys[0:-1]
        print(keys)
        print(values)

        # creating two dictionaries
        encrytDict = dict(zip(keys, values))
        decryptDict = dict(zip(values, keys))
        print(encrytDict)
        print(decryptDict)

        if text2.find('abcdefghijklmnopqrstuvwxyz1234567890 !'):
            print('true')
            newMessage = ''.join([decryptDict[letter] for letter in text2.lower()])
            print(newMessage)
            return render(request,'index.html',{'D_msg':newMessage,'text2':text2})

        else:
            print('invalid')
            invalid='Enter valid Enrypt massage'
            return render(request,'index.html',{'text2':text2,'invalid':invalid})


    return render(request,'index.html',{})


# main
def encrypt(request):
    if request.method=='POST':
        text1=request.POST.get('text1')
        # psd_e=request.POST.get('psd_e')
        print(text1)
        # print(psd_e,type(psd_e))

        # textEncrypted = make_password(psd_e)
        # print(textEncrypted,'hasher////////////////////////////',type(textEncrypted))

        # byte_psd = bytes(psd_e, 'utf-8')
        # print(byte_psd,'a/////////////////',len(byte_psd))

        # a=byte_psd.decode('utf-8')
        # print(a,'encodeedddddddddddddddddd')
        # # my_base64=base64.b64encode(byte_psd)
        # my_base64=base64.urlsafe_b64encode(byte_psd)
        # print(my_base64,'my_base64////////////////////')

        # Key should be kept safe
        key = Fernet.generate_key()
        print(key,'key////////////////////////////////',type(key))
        f= Fernet(key)
        print(f,'key')

        # a='Ajkgasduyfahv~!@#$%^&*()_+{}|?:' #manual message
        message = bytes(text1, 'utf-8')

        # Encrypt the message
        # The result of this encryption is known as a "Fernet token"
        encryptedmessage= f.encrypt(message)

        print(encryptedmessage,'encrypted message')

        decryptedmessage = f.decrypt(encryptedmessage)
        print(decryptedmessage.decode("utf-8"),'decrypted message')

        return render(request,'index.html',{'text1':text1,'fernet_key':key.decode(),'encrypt_msg':encryptedmessage.decode()})
        
    return render(request,'index.html')

def decrypt(request):
    if request.method=='POST':
        text2=request.POST.get('text2')
        psd_d=request.POST.get('psd_d')
        print(text2,type(text2),len(text2))
        print(psd_d,type(psd_d),len(psd_d))

      

        if text2 == " " and psd_d == " ":
            print('Null value **************************')
            return render(request,'index.html',{'text2':text2,'psd_key':psd_d,'error_msg':'Invalid Input'})

        elif len(psd_d) != 44:
            print('44 not ok')
            return render(request,'index.html',{'text2':text2,'psd_key':psd_d,'error_msg':'You Entered Invalid Encrypted Password'})


        elif not text2.startswith('gAAAAA'):
            print('startswith--gAAAAA and endswith-- Equals(=)')
            return render(request,'index.html',{'text2':text2,'psd_key':psd_d,'error_msg':'You Entered Invalid Encrypted Message'})
        
        # elif not text2.endswith('='):
        #     print('endswith-- Equals(=)')
        #     return render(request,'index.html',{'text2':text2,'psd_key':psd_d,'error_msg':'You Entered Invalid Encrypted Message'})
        
        else:
            print('44 ok')

        
        
            msg_key = bytes(psd_d, 'utf-8') #converting bytes
            print(msg_key,type(msg_key),len(msg_key),'//////////////msg')
            
            # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


            # bin_data = urlsafe_b64decode(text2)

            # client_data = bin_data[:-32]
            # client_hmac = bin_data[-32:]
            # print(client_data,type(client_data),'|||||||||||||||||||||||||||||')
            # print(client_hmac,type(client_hmac),'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY')

            # # print ('Client HMAC:', client_hmac.encode('hex'))
            # real_hmac = HMAC(msg_key, hashes.SHA256(), default_backend())
            # real_hmac.update(client_data)
            # real_hmac = real_hmac.finalize()
            # print(real_hmac,type(real_hmac),'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU')

            # # print ('Real HMAC  :', real_hmac.encode('hex'))
            # if client_hmac == real_hmac:
            #     print ('Token seems valid!')
            # else:
            #     print ('Token does NOT seem valid!')


            # if urlsafe_b64decode(msg_key):
            #     print('success sssssssssssssssssssssssss')
            # else:
            #     print('Faliled dddddddddddddddddddddd')
            # bin_token = urlsafe_b64decode(msg_key) # <-- c is the Fernet token you received
            # print(bin_token,type(bin_token),'aaaaaaaaaaaaaaaaaaaaaaaaaa')
            # version, timestamp = unpack('>BQ', bin_token[:9])
            # print(version,'bbbbbbbbbbbbbbbbbbbbbbbbbbbb')
            # print(timestamp,'ccccccccccccccccccccccccccccccc')
            
            # print(type(Fernet),'###########################')
            # if type(Fernet):
            #     print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
            # else:
            #     print('????????????????????????????????')
            # print('False ////////')

            
            # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
            # Key should be kept safe
            print('/////////////////////////////////////////////////////')
            # key = Fernet.generate_key()
            # print(key,'///////key',type(key))
            f= Fernet(msg_key)
            print(f,'key',type(f))


            message = bytes(text2, 'utf-8')
            print(message,type(message),'1111111111111111111111111111')

            # Encrypt the message
            # The result of this encryption is known as a "Fernet token"
            # encryptedmessage= f.encrypt(message)

            # print(encryptedmessage,'encrypted message')
            
            decryptedmessage = f.decrypt(message)
            print(decryptedmessage.decode("utf-8"),'decrypted message')

        return render(request,'index.html',{'text2':text2,'psd_key':psd_d,'decrypt_msg':decryptedmessage.decode('utf-8')})
    
    return render(request,'index.html')