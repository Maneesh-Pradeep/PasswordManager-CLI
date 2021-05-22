'''

         PASSWORD MANAGER
               CLI
              V-1.0

Author  : @maneeshpradeep AKA @manojshan
mail    : maneesh.pradeep@protonmail.com
website : www.maneeshpradeep.in
github  : github.com/maneesh-pradeep

'''

import os
import random
import secrets
from getpass import getpass
import base64
import json
import threading
import sys
import subprocess

try:
    import pyperclip
    import pyAesCrypt
    import requests
    import pyrebase
    from pyrebase.pyrebase import Storage
    from pyrebase.pyrebase import raise_detailed_error
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError:
    subprocess.call([sys.executable, "-m", "pip", "install", 'pyrebase4', 'cryptography', 'pyperclip', 'pyAesCrypt', 'requests'])
finally:
    import pyperclip
    import pyAesCrypt
    import requests
    import pyrebase
    from pyrebase.pyrebase import Storage
    from pyrebase.pyrebase import raise_detailed_error
    import cryptography
    from cryptography.fernet import Fernet
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


firebaseConfig = {
    "apiKey": "AIzaSyAhz-ekJTOEApHwajGmOtQ0_G2qqOHwpCQ",
    "authDomain": "password-manager-9190e.firebaseapp.com",
    "databaseURL": "https://password-manager-9190e.firebaseio.com",
    "projectId": "password-manager-9190e",
    "storageBucket": "password-manager-9190e.appspot.com",
    "messagingSenderId": "483899833905",
    "appId": "1:483899833905:web:af97e4de5c69cd845d9f10",
    "measurementId": "G-RNWEK4N02Q"
}

firebase = pyrebase.initialize_app(firebaseConfig)
storage = firebase.storage()
db = firebase.database()
auth = firebase.auth()


def delete(self, name, token):
    if self.credentials:
        self.bucket.delete_blob(name)
    else:
        request_ref = self.storage_bucket + "/o?name={0}".format(name)
        if token:
            headers = {"Authorization": "Firebase " + token}
            request_object = self.requests.delete(request_ref, headers=headers)
        else:
            request_object = self.requests.delete(request_ref)
        raise_detailed_error(request_object)

Storage.delete = delete


class PasswordManager:

    def __init__(self, masterpwd, uid, idToken):
        self.masterpwd = masterpwd
        self.uid = uid
        self.token = idToken


    @staticmethod
    def generate_key(password, salt=b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", length=32):
        password = password.encode()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=length,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend())

        return base64.urlsafe_b64encode(kdf.derive(password))


    @staticmethod
    def pass_gen(size=14):
        digits = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        locase_chars = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                        'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                        'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                        'z']

        upcase_chars = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                        'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
                        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                        'Z']

        symbols = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
                '*', '(', ')', '&']

        pass_chars = digits + locase_chars + upcase_chars + symbols

        rand_digit = secrets.choice(digits)
        rand_lochar = secrets.choice(locase_chars)
        rand_upchar = secrets.choice(upcase_chars)
        rand_symbol = secrets.choice(symbols)

        temp_pass = rand_digit + rand_lochar + rand_symbol + rand_upchar

        for i in range(size - 4):
            temp_pass += secrets.choice(pass_chars)

        temp_list = list(temp_pass)
        random.shuffle(temp_list)

        password = ""
        for i in temp_list:
            password += i

        return password


    def set_keys(self):
        self.key = PasswordManager.generate_key(self.masterpwd + self.uid[0:6], b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", 32)
        self.fernet = Fernet(self.key)


    def get_db(self, fernet):
        all_data = db.child("user/" + self.uid).get(self.token)
        data = []
        dataKeys = []
        headers = ['aservice', 'mail', 'password']
        try:
            for text in all_data.each():
                dataKeys.append(text.key())
                for i in headers:
                    if (i == 'password'):
                        text.val()[i] = (fernet.decrypt((text.val()[i]).encode())).decode()
                        data.append(text.val())
            self.data = data
            self.dataKeys = dataKeys
        except TypeError:
            self.add_to_db("Edit", "This", "Field")
            self.get_db(self.fernet)
        except (cryptography.exceptions.InvalidSignature, cryptography.fernet.InvalidToken):
            raise ValueError("Password Changed!")


    def add_to_db(self, serv, mail, pwd):
        temp_data = {"aservice": serv, "mail": mail, "password": (self.fernet.encrypt(pwd.encode())).decode()}
        db.child("user/" + self.uid).push(temp_data, self.token)


    def delete_from_db(self, index):
        db.child("user/" + self.uid).child(self.dataKeys[index]).remove(self.token)


    def update_db(self, index, pwd):
        self.data[index]['password'] = (self.fernet.encrypt(pwd.encode())).decode()
        upData = self.data[index]
        db.child("user/" + self.uid).child(self.dataKeys[index]).update(upData, self.token)
        
    
    def print_db_as_table(self):
        self.get_db(self.fernet)
        
        maxlen = max([len(x['aservice']) for x in self.data])
        if maxlen < 7:
            maxlen = 7
        print(f"\nINDEX\tSERVICE"+ " " * (maxlen - 7) + "\tUSER/MAIL\n")
        for i,value in enumerate(self.data):
            print(f"\n{i}\t{value['aservice']}" + " " * (maxlen - len(value['aservice'])) + f"\t{value['mail']}")

    
    def reEncrypt_db(self):
        for i, _ in enumerate(self.data):
            self.update_db(i, self.data[i]['password'])
    


class Vault:

    buffer_size = 64 * 1024
    try:
        accessLimit = int(db.child("access").get().val())
    except requests.exceptions.ConnectionError:
        print("No Internet Access!")
        exit()
        
    def __init__(self, masterpwd, uid, idToken):
        self.masterpwd = masterpwd
        self.uid = uid
        self.token = idToken
        

    @staticmethod
    def generate_key(password, salt=b"\xb9\x1f|}'S\xa1\x96\xeb\x154\x04\x88\xf3\xdf\x05", length=32):
        password = password.encode()

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        length=length,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend())

        return base64.urlsafe_b64encode(kdf.derive(password))


    @staticmethod
    def size_conv(bytes):
        unit = {1:'B', 2:'K', 3:'M', 4:'G', 5:'T'}
        if bytes==0:
            return "0B"
        for i in range(1,6):
            if(bytes < (1024**i)):
                return str(bytes//1024**(i-1)) + unit[i]


    def set_keys(self):
        self.key = Vault.generate_key(self.uid + self.masterpwd, length=64)


    def get_vault_db(self):
        all_files_data = db.child('files/'+self.uid).get(self.token)
        filesData = []
        filesKey = []
        dataUsed = 0
        try:
            for file in all_files_data.each():
                filesKey.append(file.key())
                temp = file.val()
                dataUsed += int(temp['size'])
                temp['size'] = self.size_conv(int(temp['size']))
                filesData.append(temp)
                self.data = filesData
                self.dataKeys = filesKey
                self.dataUsed = dataUsed
        except TypeError:
            with open('sample.txt', 'w') as f:
                f.write("The data you want to secure goes here")
            filenameWithExt = os.path.basename('sample.txt')+'.aes'
            filesize = os.path.getsize('sample.txt')
            self.add_to_vault('sample.txt', filenameWithExt, filesize)
            os.remove('sample.txt')
            self.get_vault_db()


    def add_to_vault(self, filepath, filenameWithExt, filesize):
        pyAesCrypt.encryptFile(filepath, filenameWithExt, self.key.decode(), Vault.buffer_size)
        storage.child('users/' + self.uid).child(filenameWithExt).put(filenameWithExt, self.token)
        temp_data = {'filename': filenameWithExt, 'size': filesize}
        db.child("files/" + self.uid).push(temp_data, self.token)
        os.remove(filenameWithExt)


    def delete_from_vault(self, index, filenameWithExt):
        storage.delete(name="users/{}/{}".format(self.uid,filenameWithExt), token=self.token)
        db.child("files/" + self.uid).child(self.dataKeys[index]).remove(self.token)
    
    
    def print_files_as_table(self):
        self.get_vault_db()
        
        maxlen = max([len(x['filename']) for x in self.data])
        if maxlen < 8:
            maxlen = 8
        print("\nINDEX\tFILENAME" + " " * (maxlen - 8) + "\tSIZE\n")
        for i,value in enumerate(self.data):
            print(f"\n{i}\t{value['filename']}" + " " * (maxlen - len(value['filename'])) +f"\t{value['size']}")

    
    def reEncrypt_vault(self):
        self.get_vault_db()
        for i,file in enumerate(self.data):
            filenameWithExt = file['filename']
            filename = filenameWithExt[:-4]
            storage.child('users/' + self.uid).child(filenameWithExt).download(path='/', filename=filenameWithExt, token=self.token)
            filesize = os.path.getsize(filenameWithExt)
            pyAesCrypt.decryptFile(filenameWithExt, filename, self.prev_vault_key, self.buffer_size)
            os.remove(filenameWithExt)

            self.delete_from_vault(i, filenameWithExt)

            self.add_to_vault(filename, filenameWithExt, filesize)
            os.remove(filename)



class User:
    
    isSessionLocked = True

    def __init__(self, email, masterpwd, uid, idToken):
        self.pwdmngr = PasswordManager(masterpwd, uid, idToken)
        self.pwdmngr.set_keys()

        self.vault = Vault(masterpwd, uid, idToken)
        self.vault.set_keys()
        
        self.email = email
        self.pwd = masterpwd
        self.uid = uid
        self.token = idToken


    @staticmethod
    def clearTerminal():
        os.system('cls' if os.name=='nt' else 'clear')


    @staticmethod
    def clearCB():
        pyperclip.copy("")
        
    
    def session_lock(self):
        if self.isSessionLocked == True:
            tempSessionPwd = getpass("\nEnter the Master Password : ")
            if tempSessionPwd == self.pwd:
                self.isSessionLocked = False
                self.clearTerminal()
                print("\nSession Unlocked!\n")
            else:
                self.clearTerminal()
                print("\nWrong Master Password!")
                return
        else:
            self.isSessionLocked = True
            self.clearTerminal()
            print("\nSession Locked!\n")

    
    def runAfterPwdReset(self):
        temp_data = db.child('temp/' + self.uid).child('key').get(self.token)
        temp_data = temp_data.val()
        vault_data = db.child('temp/' + self.uid).child('vaultkey').get(self.token)
        vault_data = vault_data.val()
        temp_key = self.pwdmngr.generate_key(self.uid)
        temp_fernet = Fernet(temp_key)
        self.temp_key = (temp_fernet.decrypt((temp_data['key']).encode())).decode()
        self.vault.prev_vault_key = (temp_fernet.decrypt((vault_data['key']).encode())).decode()
        self.temp_fernet = Fernet(self.temp_key.encode())
        db.child('temp/' + self.uid).child('key').remove(self.token)
        db.child('temp/' + self.uid).child('vaultkey').remove(self.token)
        user.pwdmngr.get_db(self.temp_fernet)
        user.pwdmngr.reEncrypt_db()
        user.pwdmngr.get_db(user.pwdmngr.fernet)
        user.vault.reEncrypt_vault()


def main(user):
    main_screen = True
    main_scr_options = ['a', 'add', 'v', 'view', 'va', 'vault', 'r', 'reset', 'l', 'lock', 'u', 'unlock',  'q', 'quit']
    user.clearTerminal()
    while main_screen:
        add_screen = False
        view_screen = False
        vault_screen = False
        reset_screen = False

        print("\nPress : (A)dd, (V)iew, (Va)ult, (R)eset, (L)ock/(U)nlock Session, (Q)uit  \n")
        main_scr_choice = input("Enter your choice : ").lower()
        if main_scr_choice not in main_scr_options:
            user.clearTerminal()
            print("\nEnter a valid choice!\n")
            continue

        if main_scr_choice == 'a' or main_scr_choice == 'add':
            main_screen = False
            add_screen = True
            while add_screen:
                user.clearTerminal()
                print("\nADD NEW ENTRY : \n")
                while True:
                    tempAddServ = input('\nEnter the Service : ')
                    tempAddMail = input('\nEnter the User/Email : ')
                    
                    if tempAddServ != '' and tempAddMail != '':
                        break
                    else:
                        print("\nFill al fields!")
                        continue
                
                while True:
                    genPass = input("\nDo you want to generate a random password?(Y/N)").lower()
                    
                    if genPass == 'y' or genPass == 'n':
                        break
                    else:
                        print("\nEnter Y or N!")
                        continue
                
                if genPass == 'y':
                    while True:
                        try:
                            passLength = int(input("\nEnter the length of the password : "))
                        except Exception:
                            print('\nOnly numbers are allowed!')
                            continue
                        
                        tempAddPwd = user.pwdmngr.pass_gen(passLength)
                        print("\nPassword Generated and copied to your clipboard and will be cleared in 10s!")
                        pyperclip.copy(tempAddPwd)
                        t = threading.Timer(10.0, user.clearCB)
                        t.start()
                        break
                        
                elif genPass == 'n':
                    while True:
                        tempAddPwd = getpass("\nEnter you Password : ")
                        
                        if tempAddPwd != '':
                            break
                        else:
                            print("\nPassword field should not be empty!")
                            continue
                
                user.pwdmngr.add_to_db(tempAddServ, tempAddMail, tempAddPwd)
                user.pwdmngr.get_db(user.pwdmngr.fernet)
                     
                print('\nEntry Successfully Added\n')
                user.clearTerminal()
                main_screen = True
                add_screen = False
                        

        elif main_scr_choice == 'v' or main_scr_choice == 'view':
            view_screen = True
            
            if user.isSessionLocked:
                tempSessionPwd = getpass("\nEnter the Master Password : ")
                if tempSessionPwd == user.pwd:
                    user.clearTerminal()
                else:
                    user.clearTerminal()
                    print("\nWrong Master Password!")
                    main_screen = True
                    view_screen = False
                    continue
            
            while view_screen:
                user.clearTerminal()
                user.pwdmngr.print_db_as_table()
                
                print("\nUsage:\nindex - To copy the password of the given index to your clipboard\nindex u - To update the password entry at the given index\nindex r - To remove the entry at the given index\nb - To go back to Main screen\n")
                
                while True:
                    tempChoiceList = input("\nEnter your choice : ").lower().split()
                    
                    if len(tempChoiceList) == 1 and tempChoiceList[0] == 'b':
                        user.clearTerminal()
                        break
                    
                    if len(tempChoiceList) == 1:
                        try:
                            tempIndex = int(tempChoiceList[0])
                        except Exception:
                            print("\nIndex should be a number!")
                            continue
                        try:
                            pyperclip.copy(user.pwdmngr.data[tempIndex]['password'])
                            print("\nPassword copied to your clipboard and will be cleared in 10s!")
                        except Exception:
                            print("\nIndex out of range!")
                            continue
                        t = threading.Timer(10.0, user.clearCB)
                        t.start()
                        
                    elif len(tempChoiceList) == 2:
                        try:
                            tempIndex = int(tempChoiceList[0])
                        except Exception:
                            print("\nIndex should be a number!")
                            continue
                        
                        if tempChoiceList[1] == 'u':
                            while True:
                                genPass = input("\nDo you want to generate a random password?(Y/N)").lower()
                                
                                if genPass == 'y' or genPass == 'n':
                                    break
                                else:
                                    print("\nEnter Y or N!")
                                    continue
                            
                            if genPass == 'y':
                                while True:
                                    try:
                                        passLength = int(input("\nEnter the length of the password : "))
                                    except Exception:
                                        print('\nOnly numbers are allowed!')
                                        continue
                                    
                                    tempUpdPwd = user.pwdmngr.pass_gen(passLength)
                                    print("\nPassword Generated and copied to your clipboard and will be cleared in 10s!")
                                    pyperclip.copy(tempUpdPwd)
                                    t = threading.Timer(10.0, user.clearCB)
                                    t.start()
                                    break
                                    
                            elif genPass == 'n':
                                while True:
                                    tempUpdPwd = getpass("\nEnter you Password : ")
                                    
                                    if tempUpdPwd != '':
                                        break
                                    else:
                                        print("\nPassword field should not be empty!")
                                        continue
                                
                            user.pwdmngr.update_db(tempIndex, tempUpdPwd)
                            user.clearTerminal()
                            print("\nEntry Successfully updated")
                            break

                        elif tempChoiceList[1] == 'r':
                            choice = input("\nAre you sure to remove this entry?(Y/N) ").lower()
                            
                            if choice == 'y':
                                user.pwdmngr.delete_from_db(tempIndex)
                                print("\nEntry Successfully removed")
                                break
                            else:
                                print("\nHappy for that :)")
                        
                        else:
                            print("\nInvaild Argument received!")
                            continue
                    
                    else:
                        user.clearTerminal()
                        print("\nInvalid arguments!")
                        continue
                
                main_screen = True
                view_screen = False

        elif main_scr_choice == 'va' or main_scr_choice == 'vault':
            vault_screen = True
            
            if user.isSessionLocked:
                    tempSessionPwd = getpass("\nEnter the Master Password : ")
                    if tempSessionPwd == user.pwd:
                        user.clearTerminal()
                    else:
                        user.clearTerminal()
                        print("\nWrong Master Password!")
                        main_screen = True
                        vault_screen = False
                        continue

            while vault_screen:
                user.clearTerminal()
                user.vault.print_files_as_table()
                
                print("\nUsage : \na - To Add a file to the vault\nindex - To Download the file\nindex r - To remove the file from the vault\nb - To go back to the Main screen\n")
                
                while True:
                    tempChoiceList = input("\nEnter your choice : ").lower().split()
                    
                    if len(tempChoiceList) == 1 and tempChoiceList[0] == 'b':
                        user.clearTerminal()
                        break
                    
                    if len(tempChoiceList) == 1 and tempChoiceList[0] == 'a':
                        print("\nTIP : Drag and drop file")
                        filepath = input("\nEnter the path of the file : ").strip()
                        filepath = os.path.expanduser(filepath)
                        filepath = os.path.abspath(filepath)
                        try:
                            tempFilename = os.path.basename(filepath)
                            tempFilenameWithExt = tempFilename+'.aes'
                            filesize = os.path.getsize(filepath)
                            if filesize <= (user.vault.accessLimit - user.vault.dataUsed):
                                if filesize <= 30*(1024**2):
                                    try:
                                        user.vault.add_to_vault(filepath, tempFilenameWithExt, filesize)
                                        user.clearTerminal()
                                        print("\nFile added successfully")
                                        break
                                    except:
                                        print('\nproblem occurred!')
                                        continue
                                else:
                                    print("\nSelect a file less than 30MB!")
                                    continue
                            else:
                                print("\nStorage limit reached! Only {} left".format(user.vault.size_conv(int(user.vault.accessLimit - user.vault.dataUsed))))
                                continue
                        except:
                            print("\nFile does Exist!")
                            continue
                    
                    if len(tempChoiceList) == 1:
                        try:
                            tempIndex = int(tempChoiceList[0])
                        except Exception:
                            print("\nIndex should be a number!")
                            continue
                        
                        try:
                            tempFileNameWithExt = user.vault.data[tempIndex]['filename']
                        except Exception:
                            print("\nIndex Out of Range!")
                            continue
                        tempFileName = tempFileNameWithExt[:-4]
                        dlPath = input("\nEnter the path to download : ")
                        dlPath = os.path.expanduser(dlPath)
                        dlPath = os.path.abspath(dlPath)
                        
                        if os.path.exists(dlPath):
                            if os.path.isdir(dlPath):
                                try:
                                    storage.child('users/' + user.uid).child(tempFileNameWithExt).download(path='/', filename=os.path.join(dlPath, tempFileNameWithExt), token=user.token)
                                    try:
                                        pyAesCrypt.decryptFile(os.path.join(dlPath, tempFileNameWithExt), os.path.join(dlPath, tempFileName), user.vault.key.decode(), user.vault.buffer_size)
                                        os.remove(os.path.join(dlPath, tempFileNameWithExt))
                                        user.clearTerminal()
                                        print("\nFile Downloaded Successfully")
                                        break
                                    except:
                                        print("\nProblem occurred while downloading!")
                                        continue
                                except:
                                    print("\nFile does not exist!")
                                    continue
                            else:
                                print("\nThe Path given is not a directory!")
                                continue
                        else:
                            print("\nPath does not exist!")
                            continue
                    
                    elif len(tempChoiceList) == 2:
                        try:
                            tempIndex = int(tempChoiceList[0])
                        except Exception:
                            print("\nIndex should be a number!")
                            continue
                        
                        if tempChoiceList[1] == 'r':
                            choice = input("\nAre you sure to remove this entry?(Y/N) ").lower()
                            
                            if choice == 'y':
                                tempFileNameWithExt = user.vault.data[tempIndex]['filename']
                                user.vault.delete_from_vault(tempIndex, tempFileNameWithExt)
                                user.clearTerminal()
                                print("\nFile Successfully removed from vault")
                                break
                            else:
                                print("\nHappy for that :)")
                        
                        else:
                            print("\nInvaild Argument received!")
                            continue
                        
                    else:
                        print("\nInvalid arguments!")
                        continue
                               
                main_screen = True
                vault_screen = False

        elif main_scr_choice == 'r' or main_scr_choice == 'reset':
            reset_screen = True
            while reset_screen:
                user.clearTerminal()
                
                print("NOTE:\nAfter resetting the password, you have to restart the program and wait for\n a min or 2 as the program decrypts and re-encrypts all of your existing\n data using your new password")
                choice = input("\nAre you sure to reset your password?(Y/N) ").lower()
                        
                if choice == 'y':
                    auth.send_password_reset_email(user.email)
                    temp_key = user.vault.generate_key(user.uid)
                    temp_fernet = Fernet(temp_key)
                    enc_uid = temp_fernet.encrypt(user.pwdmngr.key)
                    temp_data = {'key':enc_uid.decode()}
                    enc_vault = temp_fernet.encrypt(user.vault.key)
                    vault_data = {'key':enc_vault.decode()}
                    db.child('temp/'+user.uid).child('key').set(temp_data, user.token)
                    db.child('temp/'+user.uid).child('vaultkey').set(vault_data, user.token)
                    user.clearTerminal()
                    print("NOTE:\nAfter resetting the password, you have to restart the program and wait for\n a min or 2 as the program decrypts and re-encrypts all of your existing\n data using your new password")
                    print("\n\nMail has been sent to your respective account.\nNow the program will close automatically\n")
                    exit()

                else:
                    print("\nHappy for that :)")
                
                main_screen = True
                reset_screen = False
        
        elif main_scr_choice == 'l' or main_scr_choice == 'lock' or main_scr_choice == 'u' or main_scr_choice == 'unlock':
            user.session_lock()
            continue
        
        elif main_scr_choice == 'q' or main_scr_choice == 'quit':
            main_screen = False
            exit()

        else:
            print("\nInvalid choice!") # This block will not be executed
            continue


def login_sign_up():
    global email
    global pwd
    global lgn
    
    main_scr_options = ['l', 'login', 's', 'signup', 'q', 'quit']
    
    main_scr = True
    
    while main_scr:
        lgn_scr = False
        signup_scr = False
        
        print("\nPress : (L)ogin, (S)ign-up, (Q)uit  \n")
        main_scr_choice = input("Enter your choice : ").lower()
        if main_scr_choice not in main_scr_options:
            print("\nEnter a valid choice!\n")
            continue
        
        if main_scr_choice == 'l' or main_scr_choice == 'login':
            main_scr = False
            lgn_scr = True
            
            while lgn_scr:
                print("\nLogin Screen : \nType 'b' in email to go back to the Main screen\n")
                
                while True:
                    email = getpass("\nEnter your email : ")
                    
                    if email == 'b':
                        break
                    
                    pwd = getpass("\nEnter your password : ")
                    
                    if email != '' and pwd != '':
                        try:
                            lgn = auth.sign_in_with_email_and_password(email, pwd)
                            print("\nLogged in!\n")
                            return
                        except requests.exceptions.HTTPError as e:
                            error_json = e.args[1]
                            error = json.loads(error_json)['error']
                            print(f"\n{error['message']}")
                            continue
                        
                    else:
                        print("\nFill all fields!")
                        continue
                    
                lgn_scr = False
                main_scr = True
        
        elif main_scr_choice == 's' or main_scr_choice == 'signup':
            signup_scr = True
            main_scr = False
            
            while signup_scr:
                print("\nLogin Screen : \nType 'b' in email to go back to the Main screen\n")
                
                while True:
                    email = getpass("\nEnter your email : ")

                    if email == 'b':
                        break
                    
                    pwd = getpass("\nEnter your password : ")
                    cnPwd = getpass("\nConfirm your password : ")
                    
                    if email != '' and pwd != '' and cnPwd != '':
                        if pwd == cnPwd:
                            try:
                                signin = auth.create_user_with_email_and_password(email, pwd)
                                lgn = auth.sign_in_with_email_and_password(email,pwd)
                                print("\nAccount created and logged in!\n")
                                return
                            except requests.exceptions.HTTPError as e:
                                error_json = e.args[1]
                                error = json.loads(error_json)['error']
                                print(f"\n{error['message']}")
                                continue
                            
                        else:
                            print("\nPasswords does not match!")
                            continue
                    
                    else:
                        print("\nFill all fields!")
                        continue
                    
                signup_scr = False
                main_scr = True
        
        elif main_scr_choice == 'q' or main_scr_choice == 'quit':
            main_scr = False
            exit()
            
        else:
            print("\nInvalid choice!") # This block will not be executed
            continue


if __name__ == '__main__':

    try:
        login_sign_up()
    except requests.exceptions.ConnectionError:
        print("No Internet Access!")
        exit()

    id = auth.get_account_info(lgn['idToken'])
    uid = id['users'][0]['localId']

    user = User(email, pwd, uid, lgn['idToken'])
    
    try:
        user.pwdmngr.get_db(user.pwdmngr.fernet)
    except ValueError:
        user.runAfterPwdReset()
    
    try:
        db.child('temp/' + user.uid).child('key').remove(user.token)
        db.child('temp/' + user.uid).child('vaultkey').remove(user.token)
    except Exception:
        pass
    
    try:
        main(user)
    except requests.exceptions.ConnectionError:
        print("No Internet Access!")
        exit()
        

# MIT (c) Maneesh Pradeep
