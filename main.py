import time
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, DES
from Crypto.Random import get_random_bytes

data = os.urandom(1024 * 100)  # 100 KB random data
results = {}

# AES
key_aes = os.urandom(32)
iv = os.urandom(16)
start = time.time()
cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(data) + encryptor.finalize()
aes_encrypt_time = time.time() - start

start = time.time()
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
aes_decrypt_time = time.time() - start
results['AES'] = (aes_encrypt_time, aes_decrypt_time)

# RSA
key = RSA.generate(2048)
cipher_rsa = PKCS1_OAEP.new(key.publickey())
start = time.time()
ciphertext_rsa = cipher_rsa.encrypt(data[:190])
rsa_encrypt_time = time.time() - start

cipher_rsa_dec = PKCS1_OAEP.new(key)
start = time.time()
plaintext_rsa = cipher_rsa_dec.decrypt(ciphertext_rsa)
rsa_decrypt_time = time.time() - start
results['RSA'] = (rsa_encrypt_time, rsa_decrypt_time)

# DES
key_des = get_random_bytes(8)
cipher_des = DES.new(key_des, DES.MODE_ECB)
data_des = data[:1024]
start = time.time()
ciphertext_des = cipher_des.encrypt(data_des[:len(data_des) - len(data_des)%8])
des_encrypt_time = time.time() - start

start = time.time()
plaintext_des = cipher_des.decrypt(ciphertext_des)
des_decrypt_time = time.time() - start
results['DES'] = (des_encrypt_time, des_decrypt_time)

for algo in results:
    print(f"{algo} -> Encrypt: {results[algo][0]:.6f}s | Decrypt: {results[algo][1]:.6f}s")

algorithms_list = list(results.keys())
encrypt_times = [results[a][0] for a in algorithms_list]
decrypt_times = [results[a][1] for a in algorithms_list]

x = range(len(algorithms_list))

plt.bar(x, encrypt_times, width=0.4, label='Encryption', align='center')
plt.bar(x, decrypt_times, width=0.4, label='Decryption', align='edge')
plt.xticks(x, algorithms_list)
plt.ylabel("Time (seconds)")
plt.title("Encryption & Decryption Time Comparison")
plt.legend()
plt.show()
