# Gecko-IndexedDB-CacheAPI-Decryptor
This Gecko-IndexedDB-CacheAPI-Decryptor is a proof-of-concept tool. 

This tool decrypts the Client-Side Storage artifacts **(especially on IndexedDB, Cache API)** generated during the Private Session of Gecko-based browsers **(Firefox, Tor)** based on CipherKey searching in the Memory Files

# Usage
When you execute the python code, the folder selection prompt will be displayed for two times:

First prompt is for selecting the *Memory Folder Path*, and Second one is for selecting the *Encrypted DB File's Folder Path*

When the tool finishes decryption process, **the decrypted files will be saved on the same path to the original files, and result file will be saved on the same path to the tool with filename indicating the timestamp of execution**

Below is the example of the result file: it demonstrates which File was successfully decrypted by the Memory file with which Key

```plaintext
db file - caches.sqlite, memory file - firefox.exe.dmp
DECRYPT SUCCESS!! - key is 9520e6c371a218e28f436e84793fb6ea78501099c3712695f80d4fcea53ffd7a

db file - {19f4a577-8110-4ef5-a5ee-df4e57b30b06}.final, memory file - firefox.exe.dmp
DECRYPT SUCCESS!! - key is 488c91785d8bbb40ad837c56c23681ff4e7a16c9fa72abf0bca454be05c59416
```

# Note
- If the below error occurs while trying to execute the code, try to install *pycryptodome* module instead of *crypto* or *pycrypto* 

  `ModuleNotFoundError: No Module named 'Crypto'`

  **REF** - https://bobbyhadz.com/blog/python-no-module-named-crypto

- **You can decrypt multiple files at once, but It is strongly required to only put One Memory file in Memory Folder Path**

  Future version of the tool will support multiple Memory Files in one execution, but not yet

*This tool is under continuous develoption*
