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

#define PORT 8765
#define SERVER_CIPHER_LIST "SSLv2:SSLv3:TLSv1"
#define BUFSIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

void server_check_cert(SSL *ssl);
void server_request(SSL *ssl, char *request);
void server_respond(SSL *ssl, char *response);

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
    
    SSL *ssl;
    SSL_CTX *ctx;
    BIO *sbio;

    ctx = initialize_ctx(SERVER_KEYFILE, PASSWORD, SERVER);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (!SSL_CTX_set_cipher_list(ctx, SERVER_CIPHER_LIST)){
        printf("Failed to set cipher list\n");
        exit(1);
    }

  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
  
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      char buf[256];
      char *answer = "42";

      ssl = SSL_new(ctx);
      sbio = BIO_new_socket(sock, BIO_NOCLOSE);
      SSL_set_bio(ssl, sbio, sbio);

      /*
      if(SSL_connect(ssl) <= 0) {
          berr_exit(FMT_ACCEPT_ERR);
      }
      */

      int err = SSL_accept(ssl); //SSL_accept() vs ssl_connect()
      //debug info, can take this out if it works
      if (err <=0)
      {
          int errcode = SSL_get_error(ssl, err);
          switch(errcode)
          {
              case SSL_ERROR_NONE: 
                  fprintf(stderr,"uhoh spaghetti-os");
                  break;        // Cannot happen if err <=0
              case SSL_ERROR_ZERO_RETURN: 
                  fprintf(stderr,"SSL connect returned 0.");
                  break;
              case SSL_ERROR_WANT_READ: 
                  fprintf(stderr,"SSL connect: Read Error.");
                  break;
              case SSL_ERROR_WANT_WRITE: 
                  fprintf(stderr,"SSL connect: Write Error.");
                  break;
              case SSL_ERROR_WANT_CONNECT: 
                  fprintf(stderr,"SSL connect: Error connect."); 
                  break;
              case SSL_ERROR_WANT_ACCEPT: 
                  fprintf(stderr,"SSL connect: Error accept."); 
                  break;
              case SSL_ERROR_WANT_X509_LOOKUP: 
                  fprintf(stderr,"SSL connect error: X509 lookup."); 
                  break;
              case SSL_ERROR_SYSCALL: 
                  fprintf(stderr,"SSL connect: Error in system call."); 
                  break;
              case SSL_ERROR_SSL: 
                  fprintf(stderr,"SSL connect: Protocol Error.");
                  break;
              default: fprintf(stderr,"Failed SSL connect.");
          }
      }
      
      server_check_cert(ssl);

      server_request(ssl, buf);
      printf(FMT_OUTPUT, buf, answer);
      server_respond(ssl, answer);

      close(sock);
      close(s);
      return 0;
    }
  }
  destroy_ctx(ctx);
  close(sock);
  return 1;
}

void server_check_cert(SSL *ssl){
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK){
        char *resp = (char*)malloc(200 * sizeof(char));
        sprintf(resp, "ECE568-SERVER: SSL accept error\n %d:error:140890B2:SSL\n routines:SSL3_GET_CLIENT_CERTIFICATE: no\n certificate returned:s3_srvr.c:2490:", getpid());
        berr_exit(resp);
    }

    peer = SSL_get_peer_certificate(ssl);
    if (peer == NULL){
        char *resp = (char*)malloc(200 * sizeof(char));
        sprintf(resp, "ECE568-SERVER: SSL accept error\n %d:error:140890C7:SSL\n routines:SSL3_GET_CLIENT_CERTIFICATE: no\n peer did not return a certificate:s3_srvr.c:2490:", getpid());
        berr_exit(resp);
    }

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);

    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}

void server_request(SSL *ssl, char *request){
    int r; 

    r = SSL_read(ssl, request, BUFSIZE);
    switch(SSL_get_error(ssl,r)){
    case SSL_ERROR_NONE:
        break;
    case SSL_ERROR_ZERO_RETURN:
        r = SSL_shutdown(ssl);
        switch(r){
            case 1:
                break;
            default:
                berr_exit("SSL shutdown failed");
        }
    case SSL_ERROR_SYSCALL:
        berr_exit(FMT_INCOMPLETE_CLOSE);
    default:
        berr_exit("SSL read problem");
    }
}

void server_respond(SSL *ssl, char *response){
    int response_len;
    int r;
    response_len = strlen(response);

    r = SSL_write(ssl, response, response_len);
    switch(SSL_get_error(ssl,r)){      
        case SSL_ERROR_NONE:
            if(response_len!=r)
                berr_exit("Incomplete write!");
            break;
        default:
            berr_exit("SSL write problem");
    }
}
