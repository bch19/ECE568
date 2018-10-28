#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "sslsetup.c"

#define HOST "localhost"
#define PORT 8765
#define BUFSIZE 256
#define CLIENT_CIPHER_LIST "SHA1"
#define HOSTCN "Bob's Server"
#define HOSTEMAIL "ece568bob@ecf.utoronto.ca"
static int require_server_auth = 1;

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

void client_check_cert(SSL *ssl);
void client_request_response(SSL *ssl, char *request, char *response);


int main(int argc, char **argv)
{
  int sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  

  /* Set up SSL context and BIO */
  SSL *ssl;
  SSL_CTX *ctx;
  BIO *sbio;

  ctx = initialize_ctx(CLIENT_KEYFILE, PASSWORD);
  if (!SSL_CTX_set_cipher_list(ctx, CLIENT_CIPHER_LIST)){
      printf("Cipher set failed");
      exit(1);
  }
  
  /* initialize SSL */
  ssl = SSL_new(ctx);
  sbio = BIO_new_socket(sock, BIO_NOCLOSE);
  SSL_set_bio(ssl, sbio, sbio);

  if (SSL_connect(ssl) <=0){
      berr_exit(FMT_CONNECT_ERR);
  }

  if (require_server_auth){
      client_check_cert(ssl);
  }

  client_request_response(ssl, secret, buf);
  printf(FMT_OUTPUT, secret, buf);

  int shutdown_r = SSL_shutdown(ssl);

  destroy_ctx(ctx);
  close(sock);
  return 1;
}

void client_check_cert(SSL *ssl){
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];
    char issuer_CN[256];
    
    if (SSL_get_verify_result(ssl) != X509_V_OK)
        berr_exit(FMT_NO_VERIFY);
    
    peer = SSL_get_peer_certificate(ssl);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    if (strcasecmp(peer_CN, HOSTCN)) berr_exit(FMT_CN_MISMATCH);

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);
    if (strcasecmp(peer_email, HOSTEMAIL)) berr_exit(FMT_EMAIL_MISMATCH);

    X509_NAME_get_text_by_NID(X509_get_issuer_name(peer), NID_pkcs9_emailAddress, issuer_CN, 256);

    printf(FMT_SERVER_INFO, peer_CN, peer_email, issuer_CN);
}


void client_request_response(SSL *ssl, char *request, char *response){
  int len, r;

  len = strlen(request);

  r = SSL_write(ssl, request, len);
  switch(SSL_get_error(ssl,r)){      
    case SSL_ERROR_NONE:
      if(len!=r)
        berr_exit("Client SSL incomplete write!\n");
        break;
    default:
      berr_exit("Client SSL write problem");
  }

  while (1) {
    r = SSL_read(ssl, response, BUFSIZE);
    response[r]='\0';
    switch(SSL_get_error(ssl,r)){
      case SSL_ERROR_NONE:
        return;
      case SSL_ERROR_ZERO_RETURN:
        r = SSL_shutdown(ssl);
        switch(r){
          case 1:
            break;
          default:
            berr_exit("Client SSL shutdown failed");
        }
      case SSL_ERROR_SYSCALL:
        berr_exit(FMT_INCORRECT_CLOSE);
      default:
        berr_exit("Clinet SSL read problem");
    }
  }
}
