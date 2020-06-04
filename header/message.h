
#include<stdint.h> 

#define LOGIN_OPCODE 1
#define LIST_OPCODE 2
#define MATCH_OPCODE 3
#define ACK_OPCODE 4
#define DENY_OPCODE 5
#define LOGOUT_OPCODE 6
#define ERR_OPCODE 7
#define ACK_LIST 8
#define ACCEPT_OPCODE 9
#define REPLY_OPCODE 10
#define MATCH_MOVE_OPCODE 11

#define MAX_USERS 2000

#define TRUE 1
#define FALSE 0

struct message{
	uint16_t opcode;
    uint32_t my_id;
    uint16_t onlinePlayers[MAX_USERS];
    uint16_t nOnlinePlayers;
    uint32_t dest_id; // NULL if opcode != MATCH. In that case 
                      // Server thread just forward MATCH message
                      // and dest_client reply (ACK or DENY)
    uint8_t addColumn;//Used in game to specifie, in game, the Column where to add the disk
    uint32_t dest_ip;
    uint16_t my_listen_port;
    uint16_t dest_port;
    uint16_t column; 
    uint16_t flag; // 1 accept 0 deny
    uint32_t nonce;
};