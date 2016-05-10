import StringIO
import hashlib

def md5_encrypt(data, key):
	if len(data) % 16 != 0:
		data += (16 - (len(data) % 16)) * '\x00'

	hash_block = []

	output = ''
	last_hash = ''
	for c in data:
		md5_ctx = hashlib.md5()
		md5_ctx.update(c)
		md5_ctx.update(key)
		md5_ctx.update(last_hash)
		hash_block.append(md5_ctx.digest())
		last_hash = hash_block[-1]
		if len(hash_block) == 16:
			cur_block = ''
			for b in hash_block:
				cur_block += b

			md5_ctx = hashlib.md5()
			md5_ctx.update(cur_block)
			last_hash = md5_ctx.digest()
			output += cur_block + last_hash
			hash_block = []

	return output

def md5_decrypt(data, key):
	reader = StringIO.StringIO(data)
	output = ''
	last_hash = ''

	while 1:
		cur_block = ''
		for i in range(16):
			cur_hash = reader.read(16)
			if len(cur_hash) != 16:
				return output
			cur_block += cur_hash
			cur_byte = '\x00'
			for i in range(0x100):
				md5_ctx = hashlib.md5()
				cur_byte = chr(i)
				md5_ctx.update(cur_byte)
				md5_ctx.update(key)
				md5_ctx.update(last_hash)
				if cur_hash == md5_ctx.digest():
					break
			output += cur_byte
			last_hash = cur_hash
		md5_ctx = hashlib.md5()
		md5_ctx.update(cur_block)
		last_hash = reader.read(16)
		if last_hash != md5_ctx.digest():
			raise Exception("Hash mismatch! Incorrect key or corrupt data")
