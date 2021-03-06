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

  /* Set SSL context and BIO before while loop*/
  SSL *ssl;
  SSL_CTX *ctx;
  BIO *sbio;

  ctx = initialize_ctx(SERVER_KEYFILE, PASSWORD);
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
      sbio = BIO_new_socket(s, BIO_NOCLOSE);
      SSL_set_bio(ssl, sbio, sbio);

      if (SSL_accept(ssl) <=0)
      {
        berr_exit(FMT_ACCEPT_ERR);
      }
      
      server_check_cert(ssl);

      // Server request
      int r; 
      r = SSL_read(ssl, buf, BUFSIZE);
      buf[r]='\0';
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_NONE:
          break;
        case SSL_ERROR_ZERO_RETURN:
          printf("SSL connection shutdown\n");
          r = SSL_shutdown(ssl);
          switch(r){
              case 1:
                  break;
              default:
                  berr_exit("SSL connection shutdown failed");
          }
        case SSL_ERROR_SYSCALL:
          berr_exit(FMT_INCOMPLETE_CLOSE);
        default:
          berr_exit("Server SSL read problem");
      }

      printf(FMT_OUTPUT, buf, answer);
      
      // Server response
      int response_len;
      response_len = strlen(answer);
      r = SSL_write(ssl, answer, response_len);
      switch(SSL_get_error(ssl,r)){ 
          case SSL_ERROR_NONE:
            if(response_len!=r)
              berr_exit("Server incomplete write!");
            break;
          case SSL_ERROR_SYSCALL:
            berr_exit(FMT_INCOMPLETE_CLOSE);
          default:
            berr_exit("Server SSL write problem");
      }
      
      // shutdown SSL 
      int shutdown_r = SSL_shutdown(ssl);

      close(sock);
      close(s);
      return 0;
    }
  }
  // clear SSL context
  destroy_ctx(ctx);
  close(sock);
  return 1;
}

void server_check_cert(SSL *ssl){
    X509 *peer;
    char peer_CN[256];
    char peer_email[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK){
        berr_exit(FMT_ACCEPT_ERR);
    }

    peer = SSL_get_peer_certificate(ssl);
    if (peer == NULL){
        berr_exit(FMT_ACCEPT_ERR);
    }

    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_email, 256);

    printf(FMT_CLIENT_INFO, peer_CN, peer_email);
}
