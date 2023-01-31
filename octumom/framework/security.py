"""
Security system for the TrotB service.

 =====
Details
 =====

- 2048 bit RSA keys (encryption and decryption)
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from json import dumps, dump, load, loads

import base64

private_key = RSA.generate(2048)  # used for decrypting alt data
public_key = private_key.public_key()  # used for encrypting alt data

LOADED_TABLES = load(open("tables.json", "r"))

ALT_TABLE = LOADED_TABLES["alt_table"]  # saves encrypted data from alts
for i in range(len(ALT_TABLE)):
    ALT_TABLE[i] = base64.b64decode(ALT_TABLE[i].encode())

UTA_TABLE = LOADED_TABLES["uta_table"]  # saves id's with username for alts

# keys are exported and can be saved. first few bytes of the private key can be used for admin commands

key_exports = (private_key.export_key(passphrase="trot$B99"),
               public_key.export_key(passphrase="trot$B99"))

cipher_rsa = PKCS1_OAEP.new(public_key)
plaintext_rsa = PKCS1_OAEP.new(private_key)

# save the keys in a local file (data/keys.txt)


def save():
    with open("keys.txt", "wb+") as writer:
        writer.write(key_exports[0] + b"\n\n")
        writer.write(key_exports[1])

        writer.close()


"""
===== QUICK NOTE =====

Alt data is saved encrypted with the public key

Unencrypted, this is the format:

{
    "username":"sampleusername",
    "password":"password",
    "data_components":[] // other pieces of data that might be viewable in discord bot interface
}

Algorithm for adding an alt -

Fetch data from arguments
Make sure they are formatted correctly (no integers for username)
Turn the dictionary into a string or bytes and encrypt using our public key
Save the file in the ALT_TABLE, and the id of the alt using the username as the key in UTA_TABLE
"""


def add_alt(username, password, data_components: list):
    if not isinstance(username, str) or not isinstance(
            password, str) or not isinstance(data_components, list):
        print("one of the arguments is not the correct format")

        return 

    formed_alt_data = {
        "username" : username,
        "password" : password,
        "data_components" : data_components
    }

    encrypted_alt_data = cipher_rsa.encrypt(dumps(formed_alt_data).encode())

    ALT_TABLE.append(encrypted_alt_data)
    UTA_TABLE[username] = len(ALT_TABLE) - 1

def view_alt(username : str):
    if not isinstance(username, str):
        print("username argument isn't a string")

        return

    try:
        alt_id = UTA_TABLE[username]
        encrypted_alt_data = ALT_TABLE[alt_id]

        decrypted_alt_data = plaintext_rsa.decrypt(encrypted_alt_data)

        alt_data = loads(decrypted_alt_data)

        print("Username:", alt_data["username"],
             "\nPassword:", alt_data["password"],
             "\nData Components (raw):", alt_data["data_components"])
    except KeyError:
        print("error")

        return
    
# PROBLEM: when removing an alt, UTA_TABLE may need to be reformatted

def view_tables():
    CALT_TABLE = ALT_TABLE
    for i in range(len(CALT_TABLE)):
        CALT_TABLE[i] = base64.b64encode(CALT_TABLE[i]).decode()
    
    with open("tables.json", "w+") as writer:
        dump({
            "uta_table" : UTA_TABLE,
            "alt_table": CALT_TABLE
        }, writer)

        writer.close()