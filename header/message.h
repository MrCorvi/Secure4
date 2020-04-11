
#include<stdint.h> 

#define LOGIN_OPCODE 1
#define LIST_OPCODE 2
#define MATCH_OPCODE 3
#define ACK_OPCODE 4
#define DENY_OPCODE 5
#define LOGOUT_OPCODE 6
#define ERR_OPCODE 7
#define ACK_LIST 8

#define MAX_USERS 2000

struct message{
	uint16_t opcode;
    uint32_t my_id;
    uint16_t onlinePlayers[MAX_USERS];
    uint16_t nOnlinePlayers;
    uint32_t dest_id; // NULL if opcode != MATCH. In that case 
                      // Server thread just forward MATCH message
                      // and dest_client reply (ACK or DENY)
};