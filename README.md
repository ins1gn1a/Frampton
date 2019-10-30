# Frampton
PE Binary Shellcode Injector - Automated code cave discovery, shellcode injection, ASLR bypass

## Install
`pip3 install -r requirements.txt`

## Usage
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
