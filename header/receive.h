#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif


#include "../header/symEncript.h"
#include "../header/utilityFile.h"
#include "../header/keyStore.h"

extern unsigned char symKey[SIM_KEY_LEN];


void setKeyFilename(char *fn);

void setIsServerReciver();

void chaneKeyReciver(unsigned char *newKey, int size);

int deserialize_message(unsigned char* buffer, struct message *aux);

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint32_t nonce);
