#ifndef sslsetup_h
#define sslsetup_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST "568ca.pem"
#define CLIENT_KEYFILE "alice.pem"
#define SERVER_KEYFILE "bob.pem"
#define PASSWORD "password"

extern BIO *bio_err;
int berr_exit(char *string);


SSL_CTX *initialize_ctx(char *keyfile, char* password);
void destroy_ctx(SSL_CTX *ctx);

#endif
