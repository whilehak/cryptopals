import base64
from Crypto.Cipher import AES

def byteXOR(b1, b2):
	assert len(b1) == len(b2)
	ans = b''
	for i in range(len(b1)):
		xor = b1[i] ^ b2[i]
		ans += int.to_bytes(xor)
	return ans

def singleByteXOR(pt):
	possible = {}
	for num in range(1, 128):
		ans = b''
		for i in range(len(pt)):
			xor = num ^ pt[i]
			ans += int.to_bytes(xor)
		if validBytes(ans):
			possible.update({num:ans})
	if len(possible) > 1:
		for p in possible:
			print(p, possible.get(p))
		correct_key = int(input("choose key: "))
		return correct_key

	if len(possible) == 1:
		keys = list(possible.keys())
		values = list(possible.values())
		return keys[0]

def validBytes(byte):
	for b in byte:
		if b != 10 and b <= 31:
			return False
		elif b == 127 or b == 96 or b == 60:
			return False
	return True

# 1.1
pt = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
pt2 = bytes.fromhex(pt)
ans = base64.b64encode(pt2).decode()
assert ans == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

# 1.2
pt = '1c0111001f010100061a024b53535009181c'
pt2 = '686974207468652062756c6c277320657965'

pt = bytes.fromhex(pt)
pt2 = bytes.fromhex(pt2)

ans = b''
for i in range(len(pt)):
	xor = pt[i] ^ pt2[i]
	ans += int.to_bytes(xor)

ans = ans.hex()

assert ans == '746865206b696420646f6e277420706c6179'

# 1.3
pt = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
pt = bytes.fromhex(pt)

ans = b''
for num in range(1, 256):
	for i in range(len(pt)):
		xor = num ^ pt[i]
		ans += int.to_bytes(xor)
	#print(num, ans)
	ans = b''
# num = 88
#"Cooking MC's like a pound of bacon"

# 1.4
file = open('4.txt', 'r')
pts = file.readlines()

for i in range(len(pts)):
	pts[i] = pts[i].rstrip()
	pts[i] = bytes.fromhex(pts[i])

for pt in pts:
	for num in range(1, 256):
		for i in range(len(pt)):
			xor = num ^ pt[i]
			ans += int.to_bytes(xor)

		try:
			ans = ans.decode()
			front = ans[:5]
			if front.isprintable():
				pass #print(num, ans)
		except Exception as e:
			pass
		ans = b''
# num = 53
# "Now that the party is jumping\n"

# 1.5
pt = b"Burning 'em, if you ain't quick and nimble"
pt2 = b"I go crazy when I hear a cymbal"
KEY = b"ICE"

pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

ans = b''
for i in range(len(pt)):
	ans += int.to_bytes(pt[i] ^ KEY[i % 3])
ans = ans.hex()
assert ans == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'


# 1.6
file = open('6.txt', 'r')
ct = file.read()
ct = ct.replace('\n', '')
ct = base64.b64decode(ct)


for KEYSIZE in range(2, 41):
	test1 = ct[0:KEYSIZE*4]
	test2 = ct[KEYSIZE*4:KEYSIZE*8]
	counter = 0
	for i in range(len(test1)):
		byte1 = test1[i]
		byte2 = test2[i]
		str1 = "{0:08b}".format(byte1)
		str2 = "{0:08b}".format(byte2)
		for j in range(8):
			if str1[j] != str2[j]:
				counter += 1
	print(KEYSIZE, counter // KEYSIZE)
# KEYSIZE is 29

KEYSIZE = 29
cts = []
for i in range(0, len(ct), KEYSIZE):
	cts.append(ct[i:i+KEYSIZE])

KEY = ''
for blockNum in range(KEYSIZE):
	block = b''
	for shortct in cts:
		try:
			block += int.to_bytes(shortct[blockNum])
		except Exception as e:
			pass
	print(f'block {blockNum}')
	key = singleByteXOR(block)
	KEY += chr(key)
	print(key)
print(KEY)
KEY = KEY.encode()
assert KEY == b'Terminator X: Bring the noise'

ans = b''
for i in range(len(ct)):
	ans += int.to_bytes(ct[i] ^ KEY[i % KEYSIZE])
print(ans)


# 1.7 

ciphertext = open('7.txt', 'r').read()
ciphertext = base64.b64decode(ciphertext)

KEY = b'YELLOW SUBMARINE'
cipher = AES.new(KEY, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)


# 1.8
ciphertexts = open('8.txt', 'r').readlines()
ciphertexts = [ciphertext.rstrip() for ciphertext in ciphertexts]
ciphertexts = [bytes.fromhex(ciphertext) for ciphertext in ciphertexts]

for ciphertext in ciphertexts:
	ciphertextBlocks = []
	for i in range(0, len(ciphertext), 16):
		ciphertextBlocks.append(ciphertext[i:i+16])
	if len(ciphertextBlocks) != len(set(ciphertextBlocks)):
		print(ciphertext)

print('Finished')