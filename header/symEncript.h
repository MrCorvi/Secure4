
#include<stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int symEncrypt(unsigned char *msg, int pt_len, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf);

int symDecrypt(unsigned char *dec_buf, int pt_len, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf);

int getPublicKey(unsigned char *pk, uint32_t id);

int getPublicKeySize(uint32_t id);