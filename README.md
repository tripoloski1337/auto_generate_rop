Auto generate ROP
=========================

this is a simple script to quickly create an ROP chain to get a shell, it's support
x86 and x64 ELF, it uses [ropper](https://github.com/sashs/Ropper) to get all the gadget needed

Install
-------

you must install ropper to run this script, check the link below to install ropper
[ropper](https://github.com/sashs/Ropper)


Usage
---------

x86 elf
--------

    ./ropo.py -b test/hackfest-2017-ccug/haxor_login -m 10 

x64 elf
--------

     ./ropo.py -b test/defcon2019-speedrun-001/speedrun-001 -m 20

Screenshots
-----------

<img src="https://raw.githubusercontent.com/tripoloski1337/auto_generate_rop/master/screenshots/x64.png"/>

<img src="https://raw.githubusercontent.com/tripoloski1337/auto_generate_rop/master/screenshots/x86.png"/>

