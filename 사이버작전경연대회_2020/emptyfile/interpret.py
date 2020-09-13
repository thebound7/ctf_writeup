fcode = open('./code.txt', 'rb')
code = fcode.read()
fcode.close()

code_len = len(code)

flag_str = '^U_aRUS_fdJJiScSTQZasjIsVAEXanwaC0Faag_H]A_hmVjV_fXfTJT]HP'

fake_cnt = 0
loop = 0

code_rip = 0
pos = 0x3fff
memory = [0 for _ in range(0x4000)]

for i in range(0x3a):
	memory[i] = 0
memory[0x3a] = 0

order = []
const_primes = []
primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
level = 1
cnt = 0

load_start = False
load_ttl = 0
prime_start = False
prime_ttl = 0
while code_rip >= 0 and code_len > code_rip + 2:
	loop += 1
	if load_start == True:
		load_ttl += 1
		if load_ttl >= 10:
			load_ttl = 0
			load_start = False
	if prime_start == True:
		prime_ttl += 1
		if prime_ttl >= 5:
			prime_start = False
			prime_ttl = 0
			#const_primes.append(-1)
	cur_bytes = code[code_rip:code_rip+2]
	code_rip += 2
	if cur_bytes == '\n\t': # load constant value
		val = 0
		while code_len > code_rip:
			target = code[code_rip]
			code_rip += 1
			if target == '\t':
				val = ( 2 * val ) | 1
			elif target == ' ':
				val = val * 2
			else:
				break
		idx = pos
		pos -= 1
		memory[idx] = val # load value
		if level >= 1:
			print 'memory[' + hex(idx) + '] = '+hex(val)
			if val in primes and val != 2 and load_start == True and idx == 0x3fff:
				load_start = False
				load_ttl = 0
				#order.append(-1)
				prime_start = True
			if prime_start == True:
				if val in primes and val != 2:
					prime_ttl = 0
					const_primes.append(val)
	elif cur_bytes == '\n ': # jump 
		if pos > 0x3ffe:
			print 'error while jump'
			break
		
		pos += 1
		jmp_chk = memory[pos]
		if level >= 1:
			print 'if memory['+hex(pos)+'] = '+hex(memory[pos])+' == 0'
		val = 0
		while code_len > code_rip:
			target = code[code_rip]
			code_rip += 1
			if target == '\t':
				val = ( 2 * val ) | 1
			elif target == ' ':
				val = val * 2
			else:
				break
		if not jmp_chk: # jmp if 0
			if val > code_len:
				print 'fake jmp to ordinary path'
				fake_cnt += 1
				continue	
			code_rip = val
			if level >= 1:
				print 'jmp '+hex(code_rip)
		else:
			if level >= 1:
				print 'not jmp to '+hex(val)
	elif cur_bytes == '\n\n':
		if pos > 0x3ffe:
			print 'error while add pos'
			break
		pos += 1
	elif cur_bytes == '\t ':
		if pos > 0x3ffd:
			print 'error 1'
			break
		pos += 1
		val0 = memory[pos]
		pos += 1
		val1 = memory[pos]
		target_idx = pos
		pos -= 1
		memory[target_idx] = val0 - val1
		if level >= 1:
			print 'memory['+hex(target_idx)+'] = memory['+hex(target_idx-1)+'] - memory['+hex(target_idx)+'] = '+hex(val0-val1)
	elif cur_bytes == '  ':
		if pos > 0x3ffd:
			print 'error 2'
			break
		pos += 1
		val0 = memory[pos]
		pos += 1
		val1 = memory[pos]
		target_idx = pos
		pos -= 1
		memory[target_idx] = val0 + val1
		if level >= 1:
			print 'memory['+hex(target_idx)+'] = memory['+hex(target_idx-1)+'] + memory['+hex(target_idx)+'] = '+hex(val0+val1)
	elif cur_bytes == ' \n':
		if pos > 0x3ffe:
			print 'error 3'
			break
		val0 = memory[pos+1]
		target_idx = pos
		pos -= 1
		memory[target_idx] = val0
		if level >= 1:
			print 'memory['+hex(target_idx)+'] = memory['+hex(target_idx+1)+'] = '+hex(val0)
	elif cur_bytes == ' \t':
		if pos > 0x3ffd:
			print 'error 4'
			break
		pos += 1
		val0 = memory[pos]
		pos += 1
		val1 = memory[pos]
		memory[val0] = val1
		if level >= 1:
			print 'memory[memory['+hex(pos-1)+']] = memory['+hex(val0)+'] = '+hex(memory[pos])
	elif cur_bytes == '\t\n':
		if pos > 0x3ffd:
			print 'error 5'
			break
		val0 = memory[pos+1]
		memory[pos+1] = memory[pos+2]
		memory[pos+2] = val0
		if level >= 1:
			print 'memory['+hex(pos+1)+'] <-> memory['+hex(pos+2)+']'
	elif cur_bytes == '\t\t':
		if pos > 0x3ffe:
			print 'error 6'
			break
		pos += 1
		val0 = memory[pos]
		target_idx = pos
		pos -= 1
		memory[target_idx] = memory[val0]
		if level >= 1:
			print 'memory['+hex(target_idx)+'] = memory[memory['+hex(pos+1)+']] = memory['+hex(val0)+'] = '+hex(memory[val0]) 
		if val0 <= 0x3a and loop >= 30: # skip first load 0x39
			print '[*] load memory['+hex(val0)+']'
			order.append((val0, memory[0x3fff]))
			cnt += 1
			load_start = True
			load_ttl = 0
if pos <= 0x3ffe:
	print memory[pos + 1]
else:
	print 'return error'

print len(order)
print len(const_primes)
print order
print const_primes
