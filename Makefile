# Change this to point to your openssl source.
OPENSSL_DIR=openssl
CC=gcc
CFLAGS=-Wall -O3 -std=c99 -fpic -pthread -I$(OPENSSL_DIR)/include

all: token_bind_client.so token_bind_server.so base64.so

token_bind_client.so: token_bind_client.c token_bind_common.c token_bind_client.h token_bind_common.h tb_bytestring.h cbs.c cbb.c
	$(CC) $(CFLAGS) -shared -o token_bind_client.so token_bind_client.c token_bind_common.c cbs.c cbb.c

token_bind_server.so: token_bind_server.c token_bind_common.c token_bind_server.h token_bind_common.h tb_bytestring.h cbs.c cbb.c
	$(CC) $(CFLAGS) -shared -o token_bind_server.so token_bind_server.c token_bind_common.c cbs.c cbb.c

base64.so: base64.c base64.h
	$(CC) $(CFLAGS) -shared -o base64.so base64.c

clean:
	$(RM) -f token_bind_client.so token_bind_server.so base64.so
