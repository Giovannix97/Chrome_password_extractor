# Taken from the following tutorial: https://www.thepythoncode.com/article/extract-chrome-passwords-python
#
# This version creates a txt file containing all the passwords retrieved from Chrome
#
## TODO: Divide main function in different sub-functions for a clean code

import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta


def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # Decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # Remove DPAPI str
    key = key[5:]
    # Return decrypted key that was originally encrypted
    # Using a session key derived from current user's logon credentials
    # Doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    try:
        # Get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # Generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # Decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # Not supported
            return ""


def main():
    # Get the AES key
    key = get_encryption_key()

    # Local sqlite Chrome database path
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")

    # Copy the file to another location
    # As the database will be locked if chrome is currently running
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)

    # Connect to the database
    db = sqlite3.connect(filename)
    cursor = db.cursor()

    # `logins` table has the data we need
    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

    with open("final_passwords_file.txt", 'w') as final_pass_file:
        final_pass_file.write("Here you are all passwords store in Chrome: \n")

        password_text = ""

        # Iterate over all rows
        for row in cursor.fetchall():
            password_text = "\n\n"

            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]

            if username or password:
                password_text += f"Origin URL: {origin_url}\n"
                password_text += f"Action URL: {action_url}\n"
                password_text += f"Username: {username}\n"
                password_text += f"Password: {password}\n"
            else:
                continue

            if date_created != 86400000000 and date_created:
                password_text += f"Creation date: {str(get_chrome_datetime(date_created))}\n"

            if date_last_used != 86400000000 and date_last_used:
                password_text += f"Last Used: {str(get_chrome_datetime(date_last_used))}\n"

            password_text += "="*50
            final_pass_file.write(password_text)
            print(password_text)

        cursor.close()
        db.close()

        try:
            # Try to remove the copied db file
            os.remove(filename)
        except:
            pass

    # Close the file
    final_pass_file.close()


if __name__ == "__main__":
    input("Press a key to START...")
    main()
    input("Press a key to exit...")
