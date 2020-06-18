
#include "../header/symEncript.h"

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
    unsigned char *aad, int aad_len,
    unsigned char *key,
    unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag){

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
       return 0;
    
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return 0;

    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return 0;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return 0;
    ciphertext_len = len;

    //Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        return 0;
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        return 0;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}


int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
unsigned char *aad, int aad_len,
unsigned char *tag,
unsigned char *key,
unsigned char *iv, int iv_len,
unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return 0;
    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        return 0;

    //Provide any AAD data.
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return 0;

    //Provide the message to be decrypted, and obtain the plaintext output.
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return 0;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        return 0;

    /*
    * Finalise the decryption. A positive return value indicates success,
    * anything else is a failure - the plaintext is not trustworthy.
    */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);
    
    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);
    if(ret > 0) {
        /* SUCCESS */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* verify failed */
        return -1;
    }
}


int symEncrypt(unsigned char *msg, int pt_len, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf, unsigned char *aad, int aadLen){
    //Use Encryption
    gcm_encrypt(msg, pt_len, aad, aadLen, key_gem, iv_gcm, 12, cphr_buf, tag_buf);
    /*
    printf("CypherText: \n");
    BIO_dump_fp(stdout, (const char *)cphr_buf, pt_len);
    printf("Tag: \n");
    BIO_dump_fp(stdout, (const char *)tag_buf, 16);
    */

    return 0;
}


int symDecrypt(unsigned char *dec_buf, int pt_len, unsigned char *key_gem, unsigned char *iv_gcm, unsigned char *cphr_buf, unsigned char *tag_buf, unsigned char *aad, int aadLen){
    //use Decription
    gcm_decrypt(cphr_buf, pt_len, iv_gcm, 12, tag_buf, key_gem, iv_gcm, 12, dec_buf);
    /*
    printf("PlainTaxt: \n");
    BIO_dump_fp(stdout, (const char *)dec_buf, pt_len);
    */
    return 0;
}



int getPublicKey(unsigned char *pk, uint32_t id){
    // verifica
    char client_file_name[50];
    sprintf(client_file_name,"./pubkeys/ec_pubkey%d.pem", id);
    printf("File: %s\n", client_file_name);
    FILE* fp = fopen(client_file_name, "r");
    if(!fp) { 
        printf("Can't open the file of the public key !\n"); 
        return 0;
    }

    int i=0;
    while(!feof(fp)){
        pk[i] = fgetc(fp);
        printf("%c",pk[i]);   
        i++;
    }
    pk[i-1]='\0';

    printf("\nPublic key:      %s\n", pk);
    
    fclose(fp);

    return i - 1;
}


int getPublicKeySize(uint32_t id){
    // verifica
    char client_file_name[50];
    sprintf(client_file_name,"./pubkeys/ec_pubkey%d.pem", id);
    printf("File: %s\n", client_file_name);
    FILE* fp = fopen(client_file_name, "r");
    if(!fp) { 
        printf("Can't open the file of the public key !\n"); 
        return 0;
    }

    int i=0;
    rewind(fp);
    while(!feof(fp)){
        printf("%d", i);
        fgetc(fp);
        i++;
    }

    printf("Public key len: %d   \n", i);
    
    fclose(fp);

    return i-1;
}