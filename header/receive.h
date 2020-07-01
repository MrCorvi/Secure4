#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include<signal.h>
#include <pthread.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif


#include "../header/symEncript.h"
#include "../header/utilityFile.h"

extern unsigned char symKey[300];


void setKeyFilename(char *fn);

void setIsServerReciver();

void setIsAlarmFree(int flag);

void chaneKeyReciver(unsigned char *newKey, int size);

int deserialize_message(unsigned char* buffer, struct message *aux, uint8_t isEncr);

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint32_t nonce);
