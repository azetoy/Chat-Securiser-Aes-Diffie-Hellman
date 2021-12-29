import random
from Crypto.Util.number import getPrime , inverse


# On genere deux nombre premier un //2 le nombre de bits et un autre inferieur au premier generer 
# mais superieure a 0 



def gen_dh_key(bits):
    p = getPrime(bits // 2)
    g = random.randint(0, p - 1)
    return (p,g)

# On genere un chiffre random secret entre 0 et p - 1
def gen_secret(p):
    return random.randint(0, p - 1)

#on genere les cle public

def gen_dh_pubK(g, s_value, p):
    return pow(g, s_value, p)

#on genere les cle priver a partire des cle publique et d'une valeur secrete que l'on va partager
def gen_dh_pK(pub_k, s_value, p):
    return pow(pub_k ,s_value, p)

# fonction de chiffrement des message
def dh_enc(msg, p_K, p):
    enc_m = int.from_bytes(msg.encode('utf-8'),'big')
    return pow(enc_m + p_K,1,p)

# fonction de dechiffrement des message
def dh_dec(msg,p_K,p):
    dec_m = pow(msg - p_K,1,p)
    return dec_m.to_bytes((dec_m.bit_length() + 7) // 8, 'big').decode('utf-8')
