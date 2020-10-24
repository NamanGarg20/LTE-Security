LDFLAGS= -L/usr/local/opt/openssl-1.0.2-beta3/compiled/lib
CPPFLAGS= -I/usr/local/opt/openssl-1.0.2-beta3/compiled/include


all: Ciphering Integrity_check

Ciphering: Ciphering.c
	gcc $(CPPFLAGS) $(LDFLAGS) Ciphering.c -lcrypto -o Ciphering

Integrity_check: Integrity_check.c
	gcc $(CPPFLAGS) $(LDFLAGS) Integrity_check.c -lcrypto -o Integrity_check


clean:
	rm Ciphering Integrity_check
