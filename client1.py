from Crypto.Cipher import AES
from df import *
import threading
import socket
import time
#on genere nos nombre premier
p , g = gen_dh_key(2048)
can_chat = False

#fonction de crypate de message avec aes
def encrypt_aes(plaintext,key, mode):
  encobj = AES.new(key, AES.MODE_GCM)
  ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
  return(ciphertext,authTag,encobj.nonce)
#fonction de decryptage de message avec aes
def decrypt_aes(ciphertext,key, mode):
  (ciphertext,  authTag, nonce) = ciphertext
  encobj = AES.new(key,  mode, nonce)
  return(encobj.decrypt_and_verify(ciphertext, authTag))


def combine(array):
    newcc = array[0],array[1],array[2]
    return newcc

def chat(aes_k):
    print("You can chat now")
    while True:
        message = input()
        ciphertext = encrypt_aes(message.encode(),aes_k,AES.MODE_GCM)
        #le cryptage nous renvoi un triplet et on ne peut pas envoyer un tableaux avec les socket
        #du coups en envoi trois message qui seront reformer chez l'autre client pour dechiffrer le message
        send_message(ciphertext[0])
        send_message(ciphertext[1])
        send_message(ciphertext[2])

def main():
    #creation d'un thread pour le server
    server = threading.Thread(target = create_socket,args=())
    server.start()




    
def create_socket():
    #le tableaux pour regrouper nos message
    array = []
    #creation de la socket avec les parametre afnet et sock stream (TCP)
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    port = 23564
    server.bind(('127.0.0.1',port))
    print("Server binded at Port ",server.getsockname()[1])
    server.listen(1)
    print("Server is listening")
    #on accept la connection du client
    client,addr = server.accept()
    #on recupere la clé priver
    private = int(client.recv(2048).decode("ascii"))
    print("Private Key received ")
    client,addr = server.accept()
    #on recupere la cles aes chiffrer
    crypted = client.recv(2048).decode("ascii")
    print("aes Key received ")
    #on la cast en int pour pouvoir la decrypter
    dec = dh_dec(int(crypted),private,p)
    #on la convertie en bytes car une clé aes sont des bytes
    aes_k = bytes.fromhex(dec)

    chats = threading.Thread(target = chat,args=(aes_k,))
    chats.start()

    while True:
        
        client,addr = server.accept()
        a = client.recv(2048)
        #on rajoute nos triplet dans notre array pour les dechifrer
        array.append(a)
        if(len(array) == 3):
            #on les reformate pour dechiffrer le message
            dec = decrypt_aes(combine(array),aes_k,AES.MODE_GCM)
            print(dec.decode())
            array = []

    server.close()

def send_message(message):
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = '127.0.0.1'
    port = 12468
    server.connect((host,port))
    server.send(message)
    server.close()

main()

