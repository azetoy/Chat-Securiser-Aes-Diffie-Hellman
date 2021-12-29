from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from df import *
import threading
import socket
import time

# on genere nos clé publique et priver notre variable secrete et nos prime number
p , g = gen_dh_key(2048)

secret = gen_secret(p)

public = gen_dh_pubK(g,secret,p)
private = gen_dh_pK(public,secret,p)
#fonction de cryptage aes
def encrypt_aes(plaintext,key, mode):
  encobj = AES.new(key, AES.MODE_GCM)
  ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
  return(ciphertext,authTag,encobj.nonce)
#fonction de decryptage aes
def decrypt_aes(ciphertext,key, mode):
  (ciphertext,  authTag, nonce) = ciphertext
  encobj = AES.new(key,  mode, nonce)
  return(encobj.decrypt_and_verify(ciphertext, authTag))
#fonction de generation de clé aes
def genAesKey():
    return get_random_bytes(32)
aes_k = genAesKey()

#fonction pour lancer le thread de discution
def chat(aes_k):
    print("You can chat now")
    while True:
        message = input()
        ciphertext = encrypt_aes(message.encode(),aes_k,AES.MODE_GCM)

        send_message(ciphertext[0])
        send_message(ciphertext[1])
        send_message(ciphertext[2])
#fonction de combinaison de nos triplet pour en former que 1
def combine(array):
    newcc = array[0],array[1],array[2]
    return newcc

def create_socket():

    array = []

    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    port = 12468
    server.bind(('127.0.0.1',port))
    print("Server binded at Port ",server.getsockname()[1])
    server.listen(1)
    print("Server is listening")
    #pn convertie notre clé en string puis en bytes pour l'envoyer a notre client
    send_message(str(private).encode('ascii'))
    print("Private Key was sended")
    tmp = aes_k.hex()
    enc = dh_enc(tmp,private,p)
    send_message(str(enc).encode('ascii'))
    print("Aes Key was sended")


    chats = threading.Thread(target = chat,args=(aes_k,))
    chats.start()

    while True:
        client,addr = server.accept()
        a = client.recv(2048)
        array.append(a)
        if(len(array) == 3):
            dec = decrypt_aes(combine(array),aes_k,AES.MODE_GCM)
            print(dec.decode())
            array = []

    server.close()

def send_message(message):
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 23564
    server.connect((host,port))
    server.send(message)
    server.close()

def main():

    server = threading.Thread(target = create_socket,args=())
    server.start()

    time.sleep(5)


main()
