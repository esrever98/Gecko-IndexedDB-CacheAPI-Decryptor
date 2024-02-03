import json
try:
    import Crypto
except ImportError:
    import crypto
    import sys
    sys.modules['Crypto'] = crypto
from Crypto.Cipher import ChaCha20_Poly1305

from tkinter import *
from tkinter import filedialog
import re
import os
import datetime

ciphertext = b''
plaintext = b''
nonce = b''
tag = b''

#######################################################################################

def extract_key_candidates_sqlite(memory):
    pattern = b'\x07\x00\x00\x00\x21\x00\x02\x00'
    regex = re.compile(pattern)
    match_offset = []
    key_candidates = []

    f = open(memory, 'rb')
    data = f.read()

    for match_obj in regex.finditer(data):
        offset = match_obj.start()
        match_offset.append(offset)

    for idx in match_offset:
        f.seek(idx + 8)
        res = f.read(32)

        # there is very low possiblity that hash value has \x00 * 4 or \xe5 * 4
        if (b'\x00\x00\x00\x00' in res or b'\xe5\xe5\xe5\xe5' in res):
            continue
        key_candidates.append(res)
    f.close()

    sorted_key_candidates = list(set(key_candidates))
    # print('possible DB key candidates in {} are {}'.format(memory, len(sorted_key_candidates)))

    return sorted_key_candidates


def extract_key_candidates_blob(memory):

    pattern_idb_blob = b'\x01\x00\x00\x00\x05\x00\x02\x00' # in case of blob files lower than 10 in single origin
    regex = re.compile(pattern_idb_blob)
    match_offset = []
    key_candidates = []

    f = open(memory, 'rb')
    data = f.read()

    for match_obj in regex.finditer(data):
        offset = match_obj.start()
        match_offset.append(offset)

    for idx in match_offset:
        f.seek(idx + 8)
        res = f.read(32)

        # there is very low possiblity that hash value has \x00 * 4 or \xe5 * 4
        if (b'\x00\x00\x00\x00' in res or b'\xe5\xe5\xe5\xe5' in res):
            continue
        key_candidates.append(res)
    f.close()

    sorted_key_candidates = list(set(key_candidates))
    #print('possible BLOB key candidates in {} are {}'.format(memory, len(sorted_key_candidates)))

    return sorted_key_candidates


def extract_key_candidates_morgue(memory):
    pattern_cache_blob = b'\x26\x00\x00\x00\x05\x00\x02\x00'

    regex = re.compile(pattern_cache_blob)
    match_offset = []
    key_candidates = []

    f = open(memory, 'rb')
    data = f.read()

    for match_obj in regex.finditer(data):
        offset = match_obj.start()
        match_offset.append(offset)

    for idx in match_offset:
        f.seek(idx + 8)
        res = f.read(32)

        # there is very low possiblity that hash value has \x00 * 4 or \xe5 * 4
        if (b'\x00\x00\x00\x00' in res or b'\xe5\xe5\xe5\xe5' in res):
            continue
        key_candidates.append(res)
    f.close()

    sorted_key_candidates = list(set(key_candidates))
    #print('possible Morgue Cache key candidates in {} are {}'.format(memory, len(sorted_key_candidates)))

    return sorted_key_candidates


def main_func_DB(encrypted_db, sorted_key_candidates):
    output_db = encrypted_db.split('.')[0] + "_decrypted"

    target = open(output_db, "wb")
    target.close()

    source = open(encrypted_db, 'rb')
    target = open(output_db, "ab")
    i = 0

    source.seek(i)
    true_key = ""

    while (True):
        data = source.read(8192)
        if (data == b''):
            break

        ########################  Decrypt ########################
        if (data[0:15] == b'SQLite format 3'):
            target.write(data[0:32])
            ciphertext = data[32:8160]
        else:
            ciphertext = data[0:8160]

        nonce = data[8160:8172]
        tag = data[8176:8192]

        for key in sorted_key_candidates:
            try:
                decipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                decipher.update(b'')
                plaintext = decipher.decrypt_and_verify(ciphertext, tag)
                true_key = key
            except ValueError:
                continue
        ########################  Decrypt ########################

        if (true_key == ""):
            # print('something is wrong...')
            break
        i = i + 8192
        target.write(plaintext)
        target.write(
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        source.seek(i)

    target.close()
    source.close()

    return true_key


def main_func_blob(encrypted_db, sorted_key_candidates):
    output_db = encrypted_db.split('.')[0]+"_decrypted"

    target = open(output_db, "wb")
    target.close()
    
    source = open(encrypted_db, 'rb')
    target = open(output_db, "ab")
    i=0
    
    source.seek(i)

    true_key = ""
    while (True):
        plaintext = b''
        data = source.read(4096)
        if (data == b''):
            break

        ########################  Decrypt ########################
        page_len = data[0:2]
        ciphertext = data[48:4096]
        payload_len = 4048
        if(page_len != b'\xD0\x0F'):
            payload_len = int.from_bytes(page_len, "little")

            if(payload_len%16 == 0):
                temp = payload_len
            else:
                temp = (payload_len//16 + 1) * 16

            ciphertext = data[48:48+temp]
        nonce = data[16:28]
        tag = data[32:48]
        if(true_key == ""):
            for key in sorted_key_candidates:
                try:
                    decipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                    decipher.update(b'')
                    plaintext = decipher.decrypt_and_verify(ciphertext, tag)
                    true_key = key
                except ValueError as e:
                    continue
        else:
            decipher = ChaCha20_Poly1305.new(key=true_key, nonce=nonce)
            decipher.update(b'')
            plaintext = decipher.decrypt_and_verify(ciphertext, tag)
        ########################  Decrypt ########################

        if (true_key == ""):
            print('something is wrong...')
            break

        i = i + 4096
        target.write(plaintext[0:payload_len])
        source.seek(i)

    target.close()
    source.close()

    return true_key


if __name__ == "__main__":

    mem_window = Tk()
    mem_window.title('Select Path to the Memory Files Directory')
    mem_window.geometry("0x0+100+100")
    mem_window.dirName = filedialog.askdirectory()
    memory_path = mem_window.dirName

    enc_path = Tk()
    enc_path.title('Select Path to the Encrypted Files Directory')
    enc_path.geometry("0x0+100+100")
    enc_path.dirName = filedialog.askdirectory()
    encrypted_db_path = enc_path.dirName

    """
    if len(sys.argv) < 2:
        print("You must input both mem_path / encrypted file_path")
        print("usage : Gecko_IndexedDB_CacheAPI_Decrypt.py [Memory_File_Folder path] [Encrypted_File folder path]")
        sys.exit(0)
    memory_path = sys.argv[1]
    db_path = sys.argv[2]
    """
    memory_list = []
    encrypted_db_list = []

    for dirpath, dirnames, filenames in os.walk(encrypted_db_path):
        for filename in filenames:
            encrypted_db = os.path.join(dirpath, filename)
            encrypted_db_list.append(encrypted_db)

    for dirpath, dirnames, filenames in os.walk(memory_path):
        for filename in filenames:
            memory = os.path.join(dirpath, filename)
            memory_list.append(memory)

    result_file = open(datetime.datetime.now().strftime('%y%m%d_%H%M%S') + "decrypt_result.txt", "w")

    for memory_file in memory_list:
        key_list_sqlite = extract_key_candidates_sqlite(memory_file)
        key_list_blob = extract_key_candidates_blob(memory_file) + extract_key_candidates_morgue(memory_file)

        for db_file in encrypted_db_list:
            db_type = open(db_file, 'rb')
            i = 0
            db_type.seek(i)

            data = db_type.read(16)

            if (data[0:15] == b'SQLite format 3'):
                result_file.write(
                    'DB file - {}, memory file - {}\n'.format(db_file.split('\\')[-1], memory_file.split('\\')[-1]))
                result = main_func_DB(db_file, key_list_sqlite)
            else:
                result_file.write(
                    'BLOB file - {}, memory file - {}\n'.format(db_file.split('\\')[-1], memory_file.split('\\')[-1]))
                result = main_func_blob(db_file, key_list_blob)

            if (result == ""):
                continue
            else:
                result_file.write('DECRYPT SUCCESS!! - key is {}\n\n'.format(bytes.hex(result)))

        result_file.write('\n\n')
    result_file.close()

