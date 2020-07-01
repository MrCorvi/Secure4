#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/crypto.h>
#include<openssl/pem.h>
#include <openssl/rand.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif


#include "../header/symEncript.h"

extern unsigned char symKey[SIM_KEY_LEN];

void setMyId(uint32_t setId);

void setIsServerSend();

void chaneKeySend(unsigned char *newKey, int size);

int serialize_message(void* buffer, struct message *aux);

void send_message(struct message *mex, struct sockaddr_in * dest_addr,int socket, uint8_t encrypt);
