#include <netinet/in.h>
#include <stdio.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif
#ifndef COMUNICATION_H
    #define COMUNICATION_H
    #include "../header/send.h"
    #include "../header/receive.h"
#endif

//void pack_list_message(struct message* aux, uint32_t id, uint32_t nonce);
//struct message pack_list_ack();

void listRequest(struct message m, struct sockaddr_in sv_addr, int sd, pid_t pid);