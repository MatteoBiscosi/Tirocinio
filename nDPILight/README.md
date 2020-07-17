## What is it
A light version of nDPI software, developed by ntop (check [here](https://github.com/ntop/nDPI) for more infos).

## Prerequisites
For the program to run correctly, it requires a compiled nDPI software into the same directory of Tirocinio (check [here](https://github.com/ntop/nDPI/blob/dev/README.md) for infos about nDPI compiling).
Short guide:
- cd <compilation directory>
- git clone https://github.com/ntop/nDPI.git
- cd nDPI; ./autogen.sh; ./configure; make; cd ..
- git clone https://github.com/MatteoBiscosi/Tirocinio.git
- cd Tirocinio; make
  
## Run
After compiling the necessary software (described into the previous session), run `./nDPILight -h` to check options. 

### Authors
- Matteo Biscosi
