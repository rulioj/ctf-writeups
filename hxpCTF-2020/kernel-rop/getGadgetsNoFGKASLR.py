#!/usr/bin/python3

f = open('gadgets.txt', 'r')
a = f.readlines()[2:]
b = []

ropgadgets_base = 0xffffffff81000000;

for i in a[:-2]:
    if int(i.split()[0], 16) < 0xffffffff81400dc6:
        if ('mov' in i or 'pop' in i) and 'jmp' not in i:
            offset = int(i.split()[0], 16) - ropgadgets_base;
            b.append(i.replace('\n', '') + f' | ({hex(offset)})')

for j in b:
    print(j)

print(len(b))