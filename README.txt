Naman Garg
ngarg3@binghamton.edu

The summission includes
Ciphering.c
Integrity_check.c

Ciphering :
to compile: make
usage: ./Ciphering input_file.txt
output: Ciphertext:
        output_ciphertext

the program prints the output in the above format

Integrity_check
to compile: make
usage: ./Integrity_check input_file.txt
output: LAST CIPHERTEXT BLOCK : ciphertext of last cipher block
        MAC: mac output

the program prints the output in the above format, the MAC (Message Authentication Code) is the mac output.


In makefile
As the code was run in my macOS, might need to make changes in the makefile to run in other systems to run the openssl library correctly.

LDFLAGS= -L/usr/local/opt/openssl-1.0.2-beta3/compiled/lib
CPPFLAGS= -I/usr/local/opt/openssl-1.0.2-beta3/compiled/include

all: Ciphering Integrity_check

Ciphering: Ciphering.c
    gcc $(CPPFLAGS) $(LDFLAGS) Ciphering.c -lcrypto -o Ciphering

Integrity_check: Integrity_check.c
    gcc $(CPPFLAGS) $(LDFLAGS) Integrity_check.c -lcrypto -o Integrity_check

errors:
    In the ciphering part the output of last byte might come out wrong for some text, I could implement padding correctly.
    
references:
For the Aes-Cmac algorithm used in Integrity-check.c
https://tools.ietf.org/html/rfc4493#section-2.4
