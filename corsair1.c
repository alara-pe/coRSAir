#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "openssl/ssl.h"
#include "openssl/bn.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/x509.h"

#define RSA_KEYLEN 1024

/* Cargar Certificado RSA desde un fichero y return CLAVE RSA*/
RSA *loadRSAKey(char *fichero)
{
   
    X509        *cert;                 
    EVP_PKEY    *pkey;             
    RSA         *rsa;                 
    BIO         *bio;                   
    int          fd;               

    
    bio = BIO_new(BIO_s_file());                    
    fd = BIO_read_filename(bio, fichero);     

    
    if (fd != 1) {
        printf("Error al leer el fichero '%s'.\n", fichero);
        exit(1);
    }

    
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);   
    pkey = X509_get_pubkey(cert);                   
    rsa = EVP_PKEY_get1_RSA(pkey);                 
    
    if (!cert || !pkey || !rsa) {
        printf("Error al leer el certificado '%s'.\n", fichero);
        exit(1);
    }
    
    X509_free(cert);        
    EVP_PKEY_free(pkey);    
    BIO_free(bio);          

    return rsa;
}


int main(int argc, char *argv[])
{   
    if (argc != 4) {
        printf("Uso: %s <archivo_certificado1> <archivo_certificado2> <archivo_a_descifrar>\n", argv[0]);
        return (1);
    }
    //Variables del programa
    //BUFFERS
    unsigned char *buffer_entra;      //Buffer de lectura
    unsigned char *buffer_result;     //Buffer de escritura
    BN_CTX *ctx;                    //Contexto
    RSA *rsa_privada;               //Clave RSA privada
    BIO *bioprint;                  //Buffer de escritura
    BIGNUM *numero_one;                 //Numero  1
    
    //Inicializar variables certificado 1
    RSA *rsa_publica1;              //Clave RSA publica 1
    BIGNUM *numero_cert1;                //Numero Certificado 1
    BIGNUM *qmero_cert1;                //Qmero 2  
    //Inicializar variables certificado 2
    RSA *rsa_publica2;              //Clave RSA publica 2
    BIGNUM *numero_cert2;                //Numero Certificado2
    BIGNUM *qmero_cert2;                //Qmero 2

    //Primo en comun
    BIGNUM *primo_comun;                //Primo en comun

    //Variables comunes
    BIGNUM *total;                      //Total
    BIGNUM *e;                          //Exponente Clave publica
    BIGNUM *d;                          //Exponente Clave privada

    BIGNUM *fi1;                    //Numero de factores primos de N1
    BIGNUM *fi2;                    //Numero de factores primos de N2
    
    int fd;
    int len;
    
            //Iniciar variables de buffer
    buffer_entra = malloc(sizeof(unsigned char) * RSA_KEYLEN);
    buffer_result = malloc(sizeof(unsigned char) * RSA_KEYLEN);
    //Inicializar variables BigNum
    ctx = BN_CTX_new();             //Inicializar contexto
    bioprint = BIO_new_fp(stdout, BIO_NOCLOSE); //Inicializar buffer de escritura
            //Cargar RSA
    rsa_publica1 = loadRSAKey(argv[1]);
    rsa_publica2 = loadRSAKey(argv[2]);
    
    numero_one = BN_new();          //Inicializar numero 1
    qmero_cert1 = BN_new();         //Inicializar qmero certificado 1
    qmero_cert2 = BN_new();         //Inicializar qmero certificado 2
    primo_comun = BN_new();         //Inicializar primo en comun que obtendremos con gcd
    total = BN_new();               //Inicializar total
                 //Inicializar exponente clave publica
    d = BN_new();                   //Inicializar exponente clave privada
    fi1 = BN_new();                 //Inicializar numero de factores primos de N1
    fi2 = BN_new();                 //Inicializar numero de factores primos de N2
    
            
            
            
    numero_cert1 = (BIGNUM*) RSA_get0_n(rsa_publica1);
         
    numero_cert2 = (BIGNUM*) RSA_get0_n(rsa_publica2);      
        
    e = (BIGNUM*) RSA_get0_e(rsa_publica1);                 // Obtener "e" de la clave publica
    
    rsa_privada = RSA_new();
    
    BN_gcd(primo_comun, numero_cert1, numero_cert2, ctx);    
    
    BN_div(qmero_cert1, NULL, numero_cert1, primo_comun, ctx);
   
    BN_div(qmero_cert2, NULL, numero_cert2, primo_comun, ctx);  //Obtener el numero de q primos de N2
    
    
    BN_dec2bn(&numero_one, "1");
   
    BN_sub(fi1, qmero_cert1, numero_one);
    
    BN_sub(fi2, primo_comun, numero_one);
    
    BN_mul(total, fi1, fi2, ctx); 
   
    BN_mod_inverse(d, e, total, ctx);
    
    RSA_set0_key(rsa_privada, numero_cert1, e, d);
   
    RSA_set0_factors(rsa_publica1, primo_comun, qmero_cert1);
  
    RSA_set0_factors(rsa_publica2, primo_comun, qmero_cert2);
    
    printf("Certificado 1:\n");
    RSA_print(bioprint, rsa_publica1, 0);
    
    RSA_print(bioprint, rsa_privada, 0);
  
    printf("Certificado 2:\n");
    RSA_print(bioprint, rsa_publica2, 0);
  
    RSA_print(bioprint, rsa_privada, 0);
   
    fd = open(argv[3], O_RDONLY);
    if (fd < 0) {
        printf("Error al abrir el archivo de entrada");
        exit(1);
    }
    len = read(fd, buffer_entra, RSA_KEYLEN);
    if (len <= 0) {
        printf("Error al leer el archivo de entrada");
        close(fd);
        exit(1);
    } 
    RSA_private_decrypt(len, buffer_entra, buffer_result, rsa_privada, RSA_PKCS1_PADDING);
    
    printf("Mensaje cifrado:\n");
    printf("%s\n", buffer_entra);
    printf("Mensaje descifrado:\n");
    printf("%s\n", buffer_result);
    
                
    BN_CTX_free(ctx);
    BIO_free(bioprint);
                
    
    BN_free(numero_one);
    BN_free(numero_cert1);
    BN_free(qmero_cert1);
    BN_free(numero_cert2);
    BN_free(qmero_cert2);
    
    BN_free(primo_comun);
    BN_free(e);
    BN_free(d); 
    
    BN_free(total);
    BN_free(fi1);
    BN_free(fi2);
    
/*                 //Liberar memoria */
    free(buffer_entra);
    free(buffer_result);              //Cerrar archivo
    close(fd);
    //comprobar leaks de memoria
    system("leaks -q corsair");
    return 0;
    
}

    //system("leaks -q corsair");