## What is it
A light version of nDPI software, developed by ntop (check [here](https://github.com/ntop/nDPI/blob/dev/README.md) for more infos).

## Prerequisites
For the program to run correctly, it requires a compiled nDPI software into the same directory of Tirocinio (check [here](https://github.com/ntop/nDPI/blob/dev/README.md) for infos about nDPI compiling).
Short guide:
- cd \<compilation directory\>
- git clone https://github.com/ntop/nDPI.git
- cd nDPI; ./autogen.sh; ./configure; make; cd ..
- git clone https://github.com/MatteoBiscosi/Tirocinio.git
- cd Tirocinio/nDPILight; make
  
## Run
After compiling the necessary software (described into the previous session), run `./nDPILight -h` to check options. 
<br />**Important**: Required `sudo` permissions to run the program.

### Authors
- Matteo Biscosi
