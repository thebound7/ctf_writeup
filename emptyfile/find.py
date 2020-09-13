values = [(24, 84), (40, 90), (53, 78), (52, 71), (30, 108), (4, 80), (3, 80), -1, (30, 108), (47, 93), (42, 92), (7, 93), (9, 81), (18, 87), (43, 91), -1, (52, 71), (30, 108), (4, 80), (14, 96), (56, 70), (47, 93), -1, (19, 86), (29, 105), (23, 102), (14, 96), (13, 87), (41, 61), (1, 82), -1, (27, 95), (51, 83), (5, 91), -1, (52, 71), (56, 70), (15, 92), (6, 80), (54, 65), (37, 98), -1, (17, 79), (0, 98), (11, 71), (34, 59), (39, 59), (22, 71), (36, 78), -1, (24, 84), (19, 86), (21, 93), (5, 91), (45, 81), (16, 90), -1, (3, 80), (13, 87), (41, 61), (1, 82), (10, 67), (55, 82), (2, 98), -1, (8, 91), (31, 88), (28, 89), (17, 79), (0, 98), (46, 86), (11, 71), -1, (6, 80), (57, 78), (48, 72), (35, 89), (44, 87), (54, 65), -1, (45, 81), (57, 78), (48, 72), (16, 90), (35, 89), (44, 87), (50, 77), -1, (27, 95), (42, 92), (38, 82), (32, 62), -1, (45, 81), (57, 78), (48, 72), (18, 87), (28, 89), (17, 79), (0, 98), -1, (51, 83), (15, 92), (7, 93), (20, 104), (12, 88), (25, 77), -1, (14, 96), (13, 87), (41, 61), (10, 67), (55, 82), (38, 82), -1, (29, 105), (23, 102), (33, 90), (49, 98), (56, 70), (27, 95), -1, (41, 61), (55, 82), (12, 88), (0, 98), (22, 71), -1, (16, 90), (35, 89), (44, 87), (54, 65), (43, 91), (46, 86), (11, 71), (34, 59), -1, (32, 62), (20, 104), (12, 88), (25, 77), (31, 88), -1, (40, 90), (29, 105), (33, 90), (27, 95), (57, 78), (35, 89), (50, 77), -1, (5, 91), (6, 80), (9, 81), (8, 91), (31, 88), -1, (3, 80), (1, 82), (2, 98), (32, 62), (25, 77), (34, 59), (36, 78), -1, (24, 84), (40, 90), (53, 78), (19, 86), (29, 105), (23, 102), (21, 93), (33, 90), (49, 98), -1, (4, 80), (14, 96), (38, 82), (8, 91), (28, 89), (46, 86), (26, 78), -1, (13, 87), (10, 67), (20, 104), (31, 88), (17, 79), (11, 71), (39, 59), -1, (21, 93), (33, 90), (49, 98), (56, 70), (47, 93), (10, 67), (55, 82), (2, 98), -1, (18, 87), (28, 89), (54, 65), (43, 91), (46, 86), (37, 98), (26, 78), -1, (42, 92), (38, 82), (15, 92), (7, 93), (6, 80), (9, 81), (8, 91), -1, (53, 78), (23, 102), (49, 98), (51, 83), (48, 72), (44, 87), -1, (50, 77), (37, 98), (26, 78), (39, 59), (22, 71), (36, 78), -1]
const_primes = [19, 5, -1, 23, 7, -1, 7, 23, 17, -1, 7, 23, -1, 7, 11, 3, 13, 17, 5, -1, 7, 17, 11, -1, 7, 23, -1, 7, 3, 17, -1, 19, 5, -1, 13, 23, -1, 17, 5, 11, -1, 17, 3, -1, 7, 11, 17, 23, 19, -1, 11, 7, -1, 3, 13, 7, -1, 17, 23, 19, -1, 7, 11, 17, -1, 5, 19, 13, 23, -1, 23, -1, 23, 19, 13, -1, 13, 17, -1, 17, 5, 13, -1, 7, -1, -1, 17, 7, -1, 19, 23, -1, 17, -1, 11, 7, -1, 17, 7, -1, 11, 5, 3, -1, 17, 3, 7, -1]
debug_level = 0

# parse raw data
cur_value_idx = 0
cur_prime_idx = 0
group_cnt = 0
group_list = []
while cur_value_idx + 1 < len(values):	
	cnt1 = 0
	cnt2 = 0
	flag_base_list = []
	while True:
		if type(values[cur_value_idx]) != type(()):
			cur_value_idx += 1
			break
		flag_base_list.append(values[cur_value_idx])
		cur_value_idx += 1
		cnt1 += 1

	prime_list = []
	while True:
		if const_primes[cur_prime_idx] == -1:
			cur_prime_idx += 1
			break
		prime_list.append(const_primes[cur_prime_idx])
		cur_prime_idx += 1
		cnt2 += 1

	if cnt1 + cnt2 != 9: # it contains 2 constant value
		prime_list.append(2)

	group_list.append((flag_base_list, prime_list))
	
	if debug_level >= 1:
		print 'group '+str(group_cnt)
		print '{'
		print '\t values : '+str(cnt1)
		print '\t primes : '+str(cnt2)
		print '\t totals : '+str(cnt1+cnt2)
		print '}'
	group_cnt += 1

# start calculate flag
def check_range(flag_val):
	whitelist = ['\x5b', '\x5d', '\x5e', '\x5f']
	
	for target in whitelist:
		if flag_val == ord(target):
			return True
	if ord('A') <= flag_val and flag_val <= ord('Z'):
		return True
	if ord('a') <= flag_val and flag_val <= ord('z'):
		return True

	return False

flag_str = ''
maybe_primes_list = []
base_val_list_list = []
for target_idx in range(0x3a):
	maybe_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
	base_val_list = []
	for group in group_list:
		flag_base_list, prime_list = group
		check = False
		
		for flag_base in flag_base_list:
			flag_index, base_value = flag_base
			if flag_index == target_idx: # start to find target prime
				base_val_list.append(base_value)
				check = True
				break
		if check == True: # start check
			for prime in prime_list:
				if prime in maybe_primes:
					maybe_primes.remove(prime)
	
	# check out of range prime
	for base_val in base_val_list:
		for prime in maybe_primes:
			if check_range(base_val + prime) == False:
				maybe_primes.remove(prime)
	
	maybe_primes_list.append(maybe_primes)
	base_val_list_list.append(base_val_list)

# check if other group prime not affected
target_index = 0
checked_idx_list = []
while target_index < len(maybe_primes_list):
	if target_index not in checked_idx_list:
		#print target_index
		maybe_primes = maybe_primes_list[target_index]
		if len(maybe_primes) == 1: # start to remove other crash cases
			unique = maybe_primes[0]
			for group in group_list:
				flag_base_list, prime_list = group
				check = False

				for flag_base in flag_base_list:
					flag_index, base_value = flag_base
					if flag_index == target_index:
						check = True
						break
				if check == True: # remove other flag target primes
					for flag_base in flag_base_list:
						flag_index, base_value = flag_base
						# other flag index search
						if flag_index != target_index:
							# set target maybe primes list
							target_maybe_primes = maybe_primes_list[flag_index]
							if unique in target_maybe_primes:
								#print 'remove'
								target_maybe_primes.remove(unique)
								maybe_primes_list[flag_index] = target_maybe_primes
			checked_idx_list.append(target_index)
			target_index = 0
			continue
	target_index += 1

flag_str = ''
for i in range(len(maybe_primes_list)):
	prime = maybe_primes_list[i][0]
	base_val = base_val_list_list[i][0]
	flag_str += str(chr(prime+base_val))

print flag_str
			
