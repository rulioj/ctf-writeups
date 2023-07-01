from pwn import *

target = ELF('./test')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
r = process('./test')

gdb.attach(r, gdbscript='c')

system_addr = int(r.recv()[:-1], 16)
print(system_addr)
print('system addr: ' + hex(system_addr))
libc_base = system_addr-libc.symbols['system']
print('libc base addr: ' + hex(libc_base))
puts_addr = libc_base+libc.symbols["puts"]
print('puts addr: ', hex(puts_addr))

input()