
#include<stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int symEncrypt(unsigned char *msg, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf);

int symDecrypt(int pt_len, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf);