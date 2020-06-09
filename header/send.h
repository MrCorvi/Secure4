#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include <openssl/rand.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif

#include "../header/symEncript.h"


int serialize_message(void* buffer, struct message *aux);

void send_message(struct message *mex, struct sockaddr_in * dest_addr,int socket, uint8_t encrypt);
