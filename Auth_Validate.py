## 1) auth code를 관리자가 바로 사용자에게 주는 방식은 전달 해준 Auth code를 다른 PC에서 사용 가능 하므로 불가
## 따라서 사용자 정보 기반하여 Auth_code가 생성되어야 함.

## 2)CVC를 관리자가 생성하여 사용자에게 전달 해주는 방식은 전달 과장에서의 보안 문제가 있을 수 있음.
## 사용자 PC에서 자동 생성되는 CVC 방식의 위 문제점을 방지 할 수 있음.

## 3) 사용자의 ID, MAC 를 기반으로 CVD가 생성되기에, 타 PC에서 사용 방지, 동일 PC에서 타 사용자 사용도 방지 가능함.



import getpass
import hashlib
import os
from tkinter import *
#import getmac
from functools import partial
import tkinter.messagebox
from Crypto.PublicKey import RSA
#from Crypto.Cipher import PKC0S1_OAEP
import base64
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import pss



login_screen=Tk()

AuthCode_file_path = "./AUTH"
CVC_path = "./CVC"
AuthCode_file_name = "/AuthCode.enc"
CVC_Seed_file_name = "/CVC_Seed.enc"
CVD_User_file_name = "/CVC_user.enc"


Auth_Seed_KEY = b'\x9d\x96p\xdd\x95\x03\x1e\xa6\x08\xfd\xac\xf54i\xf0\x89\x01mR\x89pKT\x01\xf5^\xf9(;lI\x86'
Auth_Code_KEY = b'O\xbc\xac\xe4\xa9\xbd\xbc\xa0V=3c!\x16\xea\x1e\x18\x9b\xae\x7f?\xb6\xf89lV\xed\x17k*\xe7}'


# 암호화 복호화 후 파일 읽기 공용파 function
def read_encrypt_file(source_file) :

    encrypt_file = open(source_file, 'r')

    encrypt_file_plaintxt = encrypt_file.read()

    ## 형변환
    encrypt_file_byte = bytearray.fromhex(encrypt_file_plaintxt)

    # Create a new AES cipher object
    cipher = AES.new(Auth_Code_KEY, AES.MODE_ECB)

    try:
        # Decrypt the ciphertext and return the plaintext
        encrypt_file_plaintext = cipher.decrypt(encrypt_file_byte)
    except:
        tkinter.messagebox.showerror("Warning", "Invalid encrypt(4)")
        return

    print("dec : ", encrypt_file_plaintext)

    try:
        ## Binary array --> str
        encrypt_file_plaintext_str = str(encrypt_file_plaintext, 'utf-8')
    except:
        tkinter.messagebox.showerror("Warning", "Invalid encrypt(5)")
        return

    encrypt_file.close()

    return encrypt_file_plaintext_str

def write_encrypt_file(source_file, PlainTXT) :

    print("Write file with encypt \n path : ",source_file,'\n Text : ',PlainTXT )
    PlainTXT = bytes(PlainTXT, 'utf-8')
    encrypt_file = open(source_file, 'w')

    # Define the encryption function
    if len(PlainTXT) % 16 != 0:
        PlainTXT += b' ' * (16 - len(PlainTXT) % 16)

    # Create a new AES cipher object
    cipher = AES.new(Auth_Code_KEY, AES.MODE_ECB)

    # Encrypt the plaintext and return the ciphertext
    encrypt_file_result = cipher.encrypt(PlainTXT)

    encrypt_file.write(encrypt_file_result.hex())

    encrypt_file.close()

def Read_AuthCode():
    ## 암호화 복호화 후 파일 읽기, Authcode file 읽기
    AutoCode_plaintext_str = read_encrypt_file(AuthCode_file_path + AuthCode_file_name)

    AuthCode_element_list = AutoCode_plaintext_str.split()

    print("Authcode :", AuthCode_element_list[0], ' ', AuthCode_element_list[1], ' ', AuthCode_element_list[2], ' ',
          AuthCode_element_list[3], ' ')
    return AuthCode_element_list


def Auth_code_UI() :
    global Auth_seed_box
    global Auth_Seed_result
    global company_email_address_entry

    def Auth_code_maker():
        global Auth_Seed_result
        Auth_seed = Auth_Seed_input_box.get(1.0, END)
        Auth_seed_byte = bytearray.fromhex(Auth_seed)


        # Create a new AES cipher object
        cipher = AES.new(Auth_Seed_KEY, AES.MODE_ECB)

        # Decrypt the ciphertext and return the plaintext
        plaintext = cipher.decrypt(Auth_seed_byte)
        plaintext_str = str(plaintext,'utf-8')
        element_list = plaintext_str.split()

        # email username mac
        Auth_code_plaintext = bytes("Authcode "+str(element_list[1]) +" " +str(element_list[2]) +" "+str(element_list[3])+" "+str(element_list[4]), 'utf-8')

        print(Auth_code_plaintext)

        # Define the encryption function
        if len(Auth_code_plaintext) % 16 != 0:
            Auth_code_plaintext += b' ' * (16 - len(Auth_code_plaintext) % 16)

        # Create a new AES cipher object
        cipher = AES.new(Auth_Code_KEY, AES.MODE_ECB)

        # Encrypt the plaintext and return the ciphertext
        Auth_Code_result = cipher.encrypt(Auth_code_plaintext)
        print("Auth_Seed_result : ", Auth_Code_result)

        Auth_code_maker_box.delete("1.0", "end")
        Auth_code_maker_box.insert(END, Auth_Code_result.hex())

    def extract_property():
        Auth_seed = Auth_Seed_input_box.get(1.0,END)

        try:
            Auth_seed_byte = bytearray.fromhex(Auth_seed)

        except (ValueError, TypeError):
            extract_property_box.delete("1.0", "end")
            extract_property_box.insert(END, "[Error] this is invalid value")
            return

        # Create a new AES cipher object
        cipher = AES.new(Auth_Seed_KEY, AES.MODE_ECB)

        # Decrypt the ciphertext and return the plaintext
        plaintext = cipher.decrypt(Auth_seed_byte)

        extract_property_box.delete("1.0", "end")
        extract_property_box.insert(END, plaintext)

        print(plaintext.rstrip(b' '))


    ########### start auth verify #############



    login_screen.title("Login")
    login_screen.geometry("600x300")

    ###### line -----------------------

    logo_image = PhotoImage(file='D:/python/SigGen_DX0508/IMG/company_logo.png', master=login_screen)
    logo_label=Label(login_screen, image=logo_image)
    logo_label.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

    ###### line -----------------------
    Label(login_screen, text="input Auth Seed").grid(column=0, row=2, padx=5, pady=5)
    Auth_Seed_input_box = Text(login_screen, width=60, height=3)
    Auth_Seed_input_box.grid(column=1, row=2, padx=5, pady=5)

    ###### line -----------------------
    Button(login_screen, text="extract property", width=20, height=1, command=extract_property).grid(column=0, row=3, padx=5, pady=5)
    extract_property_box = Text(login_screen, width=60, height=3)
    extract_property_box.grid(column=1, row=3, padx=5, pady=5)

    ###### line -----------------------
    Button(login_screen, text="create auth code", width=20, height=1, command=Auth_code_maker).grid(column=0, row=4, padx=5, pady=5)
    Auth_code_maker_box = Text(login_screen, width=60, height=3)
    Auth_code_maker_box.grid(column=1, row=4, padx=5, pady=5)

    ###### line -----------------------
    Label(login_screen, text="[주의] 해당 프로그램은 당사 보안 관련 사항으로 관리자 이외에 사용 금지입니다.", foreground='red').grid(column=0,
                                                                                                           row=5,
                                                                                                           columnspan=2,
                                                                                                           padx=10,
                                                                                                           pady=10)

    login_screen.mainloop()


if __name__ == '__main__':

    ####

    # 로그인 창 UI
    Auth_code_UI()
