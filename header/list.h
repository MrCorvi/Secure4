#include <netinet/in.h>
#include <stdio.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif
#include "../header/send.h"
#include "../header/receive.h"

void pack_list_message(struct message* aux, uint32_t id);
//struct message pack_list_ack();

void listRequest(struct message m, struct sockaddr_in sv_addr, int sd);