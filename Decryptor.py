from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome import Random



def xor(block, iv):
    
    res = []
    
    for i in range(0, max(len(block), len(iv))):
        res.append(block[i % len(block)] ^ iv[i % len(iv)])
    return bytes(res)

def pkcs7_unpadding(msg, block_size=16):
    
    padding_char = msg[-1]
    
    for i in range(len(msg) - 1, len(msg) - (padding_char + 1), -1):
        if msg[i] != padding_char:
            break
    return msg[:-padding_char]

def AES_CBC_Decrypt(cypher, key, block_size=16):
    
    iv = b'\x00' * block_size
    decrypted_msg = []
    cipher = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(cypher), block_size):
        msg_block = cypher[i: i + 16]
        block = xor(msg_block, iv)
        decrypted_block = cipher.decrypt(block)
        decrypted_msg += decrypted_block
        iv = decrypted_block

    unpadded_msg = pkcs7_unpadding(decrypted_msg)
    #unpadded_msg = unpad(decrypted_msg)   //using unpad from Cryptodome.Util.Padding
    return bytes(unpadded_msg)


if __name__ == '__main__':

    cypher = input("Cypher: ")
    key = input("Key: ")
    block_size = 16

    msg = AES_CBC_Decrypt(bytes.fromhex(cypher), bytes(key, 'utf-8'), block_size)
    print(msg.decode())