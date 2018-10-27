#include <openssl/ssl.h>
#include <openssl/err.h>
#include "sslsetup.h"


BIO *bio_err = 0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);

int berr_exit(char *string){
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(1);
}


static int password_cb(char *buf,int num, int rwflag,void *userdata){
    if(num<strlen(pass)+1){
        return(0);
    }

    strcpy(buf,pass);
    return(strlen(pass));
}


static void sigpipe_handle(int x){
}


SSL_CTX *initialize_ctx(char* keyfile, char* password, int type) {
    SSL_CTX *ctx;

    if (!bio_err) {
        /* Global system initialization */
        SSL_library_init();
        SSL_load_error_strings();

        /* An error write context */
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handelr */
    signal(SIGPIPE, sigpipe_handle);

    /* Create context */
    switch(type){      
        case CLIENT:
            ctx = SSL_CTX_new(SSLv3_client_method());
        case SERVER:
            ctx = SSL_CTX_new(SSLv23_server_method());
        default:
            ctx = SSL_CTX_new(SSLv23_method());
    }

    /* Load our keys and certificates */
    if (!(SSL_CTX_use_certificate_chain_file(ctx, keyfile))){
        berr_exit("Can't read certificate file");
    }

    pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    
    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM))){
        berr_exit("Can't read key file");
    }

    /* Load the CA we trust */
    if (!(SSL_CTX_load_verify_locations(ctx, CA_LIST,0))){
        berr_exit("Can't read CA list");
    }
      
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    return ctx;
}

void destroy_ctx(SSL_CTX *ctx){
    SSL_CTX_free(ctx);
    return;
}
