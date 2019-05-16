#coding=utf-8
#pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
import os
import base64
import argparse
import chardet

private_name = 'my_private_rsa_key.bin'
public_name = 'my_rsa_public.pem'


class FileRsa(object):
    def __init__(self):
        self.private_file_name = 'my_private_rsa_key.bin'
        self.public_file_name = 'my_rsa_public.pem'
        self.code = 'abc'
        self.CreateRSAKeys()

    def CreateRSAKeys(self):
        if not (os.path.exists(self.private_file_name) and  os.path.exists(self.public_file_name)): 
            key = RSA.generate(2048)
            encrypted_key = key.exportKey(passphrase=self.code, pkcs=8)#, protection="scryptAndAES128-CBC")
            # 私钥
            with open(self.private_file_name, 'wb') as f:
                f.write(encrypted_key)
            # 公钥
            with open(self.public_file_name, 'wb') as f:
                f.write(key.publickey().exportKey())
            
        self.public_key = RSA.import_key(open(self.public_file_name).read())
        self.public_encrypter = PKCS1_OAEP.new(self.public_key)
        self.private_key = RSA.import_key(open(self.private_file_name).read(), passphrase=self.code)
        self.private_decrypter = PKCS1_OAEP.new(self.private_key)
        self.encrypt_block = 200
        self.decrypt_block = 256;
    #tested
    def Encrypt(self, filename):
        encrypted_data = ''
        with open(filename, 'rb') as f:
            data = f.read()
            #分块加密
            for i in range(0, len(data), self.encrypt_block):
                encrypted_data = encrypted_data + self.public_encrypter.encrypt(data[i : i+self.encrypt_block])

        with open(filename, 'wb') as out_file:
            out_file.write(encrypted_data)
    #tested       
    def Descrypt(self, filename):
        decrypt_data = ''
        with open(filename, 'rb') as in_file:
            ciphertext = in_file.read()
            #分块解密
            for i in range(0, len(ciphertext), self.decrypt_block):
                decrypt_data = decrypt_data + self.private_decrypter.decrypt(ciphertext[i: i+self.decrypt_block])
        
        with open(filename, 'wb') as f:
            f.write(decrypt_data)
    #not tested
    def RenameFile(self, dir,filename):
        filename_bytes = filename.encode('utf-8')
        filename_bytes_base64 = base64.encodestring(filename_bytes)
        
        filename_bytes_base64 = filename_bytes_base64[::-1][1:]
        new_filename = filename_bytes_base64.decode('utf-8') + '.crypt1'
        print(os.path.join(dir, filename))
        print(os.path.join(dir,new_filename))
        os.rename(os.path.join(dir, filename), os.path.join(dir,new_filename))
    #not tested
    def ReserveFilename(self, dir, filename):
        f = filename
        filename = filename[::-1][7:][::-1]
        filename_base64 = filename[::-1] + '\n'
        filename_bytes_base64 = filename_base64.encode('utf-8')
        ori_filename = base64.decodestring(filename_bytes_base64).decode('utf-8')
        print(os.path.join(dir, f))
        print(os.path.join(dir,ori_filename))
        os.rename(os.path.join(dir, f),os.path.join(dir,ori_filename))
    
def Main(rootDir, mode):
    file_ras = FileRsa()
    list_dirs = os.walk(rootDir) 
    for root, dirs, files in list_dirs: 
        # 切换加密和解密过程
        if mode == 'e': 
            # 遍历文件，加密
            for f in files: 
                filename = os.path.join(root, f)
                file_ras.Encrypt(filename)
        elif mode == 'd':   
            # 遍历文件，解密
            for f in files: 
                filename = os.path.join(root, f)
                file_ras.Descrypt(filename)
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", required = True, choices = ['e', 'd'], type = str)
    args = parser.parse_args()
    d = './data'
    Main(d, args.mode)
