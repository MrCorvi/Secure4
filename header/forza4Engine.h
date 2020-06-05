#include <stdio.h>
#include <netinet/in.h>

#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"../header/message.h"
#endif
#include "../header/send.h"
#include "../header/receive.h"

#define TRUE 1
#define FALSE 0

#define MAP_WIDTH 7
#define MAP_HEIGHT 5

#define VOID 0
#define PLAYER_LOCAL 1
#define PLAYER_HOST 2

void forza4Engine(char *destIp, int destPort , int sendSd, int reciveSd, int first);