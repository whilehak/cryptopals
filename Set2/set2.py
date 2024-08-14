from Crypto.Cipher import AES
import base64, secrets

def byteXOR(b1, b2):
	assert len(b1) == len(b2)
	ans = b''
	for i in range(len(b1)):
		xor = b1[i] ^ b2[i]
		ans += int.to_bytes(xor)
	return ans

def PKCS7padding(block, length):
	paddingNum = length - len(block)
	padding = int.to_bytes(paddingNum)

	return block + padding * paddingNum

# 2.9
assert PKCS7padding(b'YELLOW SUBMARINE', 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04"

# 2.10

ciphertext = open('10.txt', 'r').read()
ciphertext = base64.b64decode(ciphertext)

KEY = b'YELLOW SUBMARINE'
IV = b'\x00' * 16
cipher = AES.new(KEY, AES.MODE_ECB)

fullPlaintext = ''
for i in range(0, len(ciphertext), 16):
	block = ciphertext[i:i+16]
	plaintext = cipher.decrypt(block)
	if i == 0:
		plaintext = byteXOR(IV, plaintext)
	else:
		plaintext = byteXOR(ciphertext[i-16:i], plaintext)
	fullPlaintext += plaintext.decode()
#print(fullPlaintext)

# 2.11

def randomAESKEY():
	return secrets.token_bytes(16)

def encryption_oracle(plaintext):
	# plaintext in bytes
	KEY = randomAESKEY()
	randomBytes = secrets.token_bytes(secrets.randbelow(6) + 5)
	randomBytes2 = secrets.token_bytes(secrets.randbelow(6) + 5)
	plaintext = randomBytes + plaintext + randomBytes2
	if secrets.randbelow(2) == 0: #ECB
		print('ECB')
		cipher = AES.new(KEY, AES.MODE_ECB)
	else:
		print('CBC')
		cipher = AES.new(KEY, AES.MODE_CBC, secrets.token_bytes(16))
	ciphertext = cipher.encrypt(PKCS7padding(plaintext, len(plaintext) // 16 * 16 + 16))
	return ciphertext


def detection_oracle(ciphertext):
	ciphertextBlocks = []
	for i in range(0, len(ciphertext), 16):
		ciphertextBlocks.append(ciphertext[i:i+16])
	if len(ciphertextBlocks) != len(set(ciphertextBlocks)):
		return 'ECB'
	else:
		return 'CBC'


encrypted = encryption_oracle(b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
#print(encrypted)

detected = detection_oracle(encrypted)
#print(detected)

# 2.12 

def encryption12(plaintext):
	KEY = b'NANOTECHNOLOGIES'
	plaintext = plaintext + base64.b64decode(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

	cipher = AES.new(KEY, AES.MODE_ECB)
	ciphertext = cipher.encrypt(PKCS7padding(plaintext, len(plaintext) // 16 * 16 + 16))
	return ciphertext

'''
def ECB_block_detector(ciphertext, num):
	ciphertextBlocks = []
	for i in range(0, len(ciphertext), num):
		ciphertextBlocks.append(ciphertext[i:i+num])
	
	for i in range(len(ciphertextBlocks)): # remove incomplete ciphertext blocks
		if len(ciphertextBlocks[i]) != num:
			ciphertextBlocks.remove(ciphertextBlocks[i])

	if len(ciphertextBlocks) != len(set(ciphertextBlocks)): # repeating block
		print(num)

for i in range(1, 100):
	plaintext = b'A' * i * 2 # two blocks of repeated characters
	ciphertext = encryption12(plaintext)
	#ECB_block_detector(ciphertext, i)
'''

blockSize = 16

short_input = b'A' * (blockSize - 1)
short_output = encryption12(short_input)

for i in range(65, 91):
	input_block = b'A' * (blockSize - 1) + int.to_bytes(i)
	output = encryption12(input_block) # last byte is unknown text
	if short_output[:16] == output[:16]:
		print(input_block)


known_padding = b''
for i in range(1, 144):
	default_input = b'A' * (blockSize * 10 - i)
	length = len(default_input) + 1
	default_output = encryption12(default_input)

	for j in range(0, 128):
		input_block = default_input + int.to_bytes(j) # AAA...AA_
		output = encryption12(input_block)
		if output[:length] == default_output[:length]:
			known_padding += int.to_bytes(j)
			print(known_padding)





































