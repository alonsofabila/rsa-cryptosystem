# Practica de Algoritmo RSA
# Cifrado de mensaje

import Crypto.Util.number
import Crypto.Random


# Numero de bits
bits = 1024

# Obtener los primos para Alice y Bob
prime_Alice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAlice = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print(f'prime Alice: {prime_Alice}')
print(f'qAlice: {qAlice}')

prime_Bob = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qBob = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
print(f'\nprime Bob: {prime_Bob}')
print(f'qBob: {qBob}')

# Obtenemos la primera parte de la llave publica de alice y bob
nAlice = prime_Alice * qAlice
nBob = prime_Bob * qBob
print(f'\nAlice: {nAlice}')
print(f'nBob: {nBob}')

# Calculamos el indficador de Eruler Phi
phiAlice = (prime_Alice - 1) * (qAlice - 1)
phiBob = (prime_Bob - 1) * (qBob - 1)
print(f'\nphiAlice: {phiAlice}')
print(f'\nphiBob: {phiBob}')

# Por razones de eficiencia usaremos el numero 4 de Fer,at, 65537, debido a que es un numero primo largo y no es
# potencia de 2, y como forma parte de la clve piublica no es necesario calcularlo
e = 65537

# Calcular la lalve privada de Alice y Bob
dAlice = Crypto.Util.number.inverse(e, phiAlice)
dBob = Crypto.Util.number.inverse(e, phiBob)
print(f'\ndAlice: {dAlice}')
print(f'dBob: {dBob}')

# Crifrar mensaje
msg = 'Y la de chambear no se la saben?'

print(f'\nMensaje Original: {msg}')
print(f'Longitud mensaje en bytes: {len(msg.encode('utf-8'))}')

# Convertir el mensaje a numero
m = int.from_bytes(msg.encode('utf-8'), byteorder='big')
print(f'Mensaje convvertido a entero: {m}')

# Ciframos el mensaje
c = pow(m, e, nBob)
print(f'\nMensaje cifrado: {c}')

# Desiframos el mensaje
des = pow(c, dBob, nBob)
print(f'mensaje descifrado: {des}')

# Convertir el mensaje descifrado a texto
msg_final = int.to_bytes(des, len(msg), byteorder='big')
print(f'\nMensaje final: {msg_final}')
