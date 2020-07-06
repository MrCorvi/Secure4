#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif


#include "../header/symEncript.h"
#include "../header/utilityFile.h"
#include "../header/keyStore.h"

extern unsigned char symKey[SIM_KEY_LEN];
extern int isClinetSecondProcess;
extern int waitTime;

extern void pingHandler(struct message m_ping, struct sockaddr *addr);


void setKeyFilename(char *fn);

void setIsServerReciver();

void setIsAlarmfree(int flag);

void setExitOnError(int flag);

void chaneKeyReciver(unsigned char *newKey, int size);

void changeKeyClientReciver(unsigned char *newKey, int size);

int deserialize_message(unsigned char* buffer, struct message *aux, uint8_t isEncr);

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint64_t nonce);
