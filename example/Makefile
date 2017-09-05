# Change this to point to your openssl installation.
OPENSSL_DIR=/usr/local

CC=gcc
CFLAGS=-D_GNU_SOURCE -Wall -Wextra -O3 -std=c99 -fpic -pthread -I$(OPENSSL_DIR)/include -I..
#CFLAGS=-D_GNU_SOURCE -Wall -Wextra -g -std=c99 -fpic -pthread -I$(OPENSSL_DIR)/include -I..
LIBS= $(OPENSSL_DIR)/lib/libssl.a $(OPENSSL_DIR)/lib/libcrypto.a -ldl

all: client server unescape

client: client.c
	$(CC) $(CFLAGS) -o client client.c ../token_bind_client.so ../base64.so $(LIBS)

server: server.c
	$(CC) $(CFLAGS) -o server server.c ../token_bind_server.so ../base64.so $(LIBS)

unescape: unescape.c
	$(CC) $(CFLAGS) -o unescape unescape.c ../token_bind_server.so ../base64.so $(LIBS)

clean:
	rm -f client server key_vault cookie_jar unescape
