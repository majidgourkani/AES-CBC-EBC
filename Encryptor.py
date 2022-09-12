from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome import Random



def xor(block, iv):
    
    res = []
    
    for i in range(0, max(len(block), len(iv))):
        res.append(block[i % len(block)] ^ iv[i % len(iv)])
    return bytes(res)


def pkcs7_padding(msg, block_size):
    r_value  = len(msg) % block_size
    if r_value == 0:
        padding_char = '\x10'
        return msg + padding_char * block_size
    else:
        padding_char = chr(block_size-r_value)
        return msg + padding_char * (block_size-r_value)


def AES_CBC_Encrypt(data, key, block_size=16):
    
    padded_data = bytes(pkcs7_padding(data, block_size),'utf-8')
    #padded = pad(bytes(data,'utf-8'), 16) //using pad from Cryptodome.Util.Padding
    iv = b'\x00' * block_size
    encrypted_msg = []
    cipher = AES.new(key, AES.MODE_ECB)

    for i in range(0, len(padded_data), block_size):
        msg_block = padded_data[i: i + block_size]
        block = xor(msg_block, iv)
        encrypted_block = cipher.encrypt(block)
        encrypted_msg += encrypted_block
        iv = encrypted_block

    return bytes(encrypted_msg)


if __name__ == '__main__':
    
    msg = input("Message: ")
    key = input("Key: ")
    block_size = 16
        
    if len(key) != block_size:
        print("Key should be {} Bytes".format(block_size))
        exit()

    c_msg = AES_CBC_Encrypt(msg, bytes(key, 'utf-8'), block_size)
    print(c_msg.hex())