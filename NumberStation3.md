# NumberStation3 challenge

## Recon

In this challenge, we are given the encryption script used to encrypt the flag. The script is as follows:

```py
# Python Module ciphersuite
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from binascii import hexlify, unhexlify

FLAG_FILE = '/flags/flag.txt'

# Use crypto random generation to get a key with length n
def gen(): 
    rkey = bytearray(os.urandom(16))
    for i in range(16): rkey[i] = rkey[i] & 1
    return bytes(rkey)

# Bitwise XOR operation.
def enc(k, m):
    cipher = Cipher(algorithms.AES(k), modes.ECB())
    encryptor = cipher.encryptor()
    cph = b""
    for ch in m:
        cph += encryptor.update((ch*16).encode())
    cph += encryptor.finalize()
    return cph

# Reverse operation
def dec(k, c):
    assert len(c) % 16 == 0
    cipher = Cipher(algorithms.AES(k), modes.ECB())
    decryptor = cipher.decryptor()
    blocks = len(c)//16
    msg = b""
    for i in range(0,(blocks)):
        msg+=decryptor.update(c[i*16:(i+1)*16])
        msg=msg[:-15]
    msg += decryptor.finalize()
    return msg

with open(FLAG_FILE, 'r') as fd:
    un_flag = fd.read()

k = gen()
print(hexlify(enc(k, un_flag)).decode())
sys.stdout.flush()
```

As we can see, the flag is read to the variable `un_flag`. Then, an AES key, `k` is generated using the `gen()` method.
Finally, `un_flag` is encrypted using `k` and the result is printed to the standard output.

As far as this top-level procedure goes, it doesn't seem vulnerable, therefore, the vulnerability must be within either `gen()` or `enc(k, un_flag)`.

```py
# Bitwise XOR operation.
def enc(k, m):
    cipher = Cipher(algorithms.AES(k), modes.ECB())
    encryptor = cipher.encryptor()
    cph = b""
    for ch in m:
        cph += encryptor.update((ch*16).encode())
    cph += encryptor.finalize()
    return cph
```

The `enc` method has been copied above. 

As we can see, the AES mode used is ECB (or Electronic Code Book). This means that, for the same message and key, the same encrypted output will be produced, since no salt is used. This could be useful in other situations, however, in this situation, we are interested in decrypting the message and, as such, this is of no value.

Other than what was said above, it looks like no other vulnerabilities can be exploited in the `enc` method.

The other point of failure could be `gen()`.

```py
# Use crypto random generation to get a key with length n
def gen(): 
    rkey = bytearray(os.urandom(16))
    for i in range(16): rkey[i] = rkey[i] & 1
    return bytes(rkey)
```

In `gen`, an array of 16 random bytes (128 bits) is generated.

A 128-bit key is generally very secure, nowadays. The number of possible keys is 2^128, which is an exceedingly large number. As such, it would be very hard to brute-force the key. However, the line `for i in range(16): rkey[i] = rkey[i] & 1` makes it so that each of the bytes is mapped to its first bit. As such, the 128-bit key is effectively reduced to a 16-bit key. The number of possible keys, with a 16-bit key, is 2^16 = 65536, which means that we can easily brute-force the key, especially given that AES can be hardware-accelerated.

We can confirm this by printing the key after it's generated.

![Keys generated using gen()](/images/numberstation3/keys.png)

As you can see, the keys generated are 128-bit long, however, there are only 16-bits that can have their value different from 0.

Using what we just learned, we can brute-force the key, using the already provided `dec` method and checking if the decrypted output contains the substring `flag`.

## Exploitation

Brute-forcing a 16-bit key is relatively simple. In this case, however, we need to transform the 16-bit key into a 128-bit key. As such, we can check to see if a bit set in the 16-bit key and, if it is, set the corresponding byte in the 128-bit key to 1. If it isn't, set it to 0.

As such, we can generate all 128-bit keys with 16 bits of randomness using the following code:

```py
masks = [2**i for i in range(0, 16)]

for possible_key in range(0, 2**16):
    key = [0] * 16
    
    for i in range(0, 16):
        if possible_key & masks[i]: # "if bit `i` is set"
            key[i] = 1

    key = bytes(key)
```

After having all of the keys generated, we can decrypt the flag using them and check what results contain the substring `flag`.

```py
try:
    flag_bytes = b'flag'
    dec_bytes = dec(key, unhexlify(ENC_FLAG))
    if flag_bytes in dec_bytes:
        print(dec_bytes.decode())
except:
    pass
```

### Final Exploit

The final exploit is as follows:

```py
# Python Module ciphersuite
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from binascii import hexlify, unhexlify

ENC_FLAG = "f5fc80417d833c7381ca730..." # shortened for brevity

# Reverse operation
def dec(k, c):
    assert len(c) % 16 == 0
    cipher = Cipher(algorithms.AES(k), modes.ECB())
    decryptor = cipher.decryptor()
    blocks = len(c)//16
    msg = b""
    for i in range(0,(blocks)):
        msg+=decryptor.update(c[i*16:(i+1)*16])
        msg=msg[:-15]
        msg += decryptor.finalize()
    return msg

masks = [2**i for i in range(0, 16)]
for possible_key in range(0, 2**16):
    key = [0] * 16
    for i in range(0, 16):
        if possible_key & masks[i]:
            key[i] = 1
    key = bytes(key)
    try:
        flag_bytes = b'flag'
        dec_bytes = dec(key, unhexlify(ENC_FLAG))
        if flag_bytes in dec_bytes:
            print(dec_bytes.decode())
    except:
        pass
```

Having the exploit made, we just need to connect to the server, using `nc ctf-fsi.fe.up.pt 6002`, and then copy the encrypted flag to the `ENC_FLAG` variable. After that, we just executed the exploit and the unencrypted flag was printed.
