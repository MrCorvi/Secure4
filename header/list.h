#include <netinet/in.h>
#include <stdio.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif
#include "../header/send.h"
#include "../header/receive.h"

void pack_list_message(struct message* aux);

void listRequest(struct message m, struct sockaddr_in sv_addr, int sd);