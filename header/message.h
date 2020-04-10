
#include<stdint.h> 

#define LOGIN_OPCODE 1
#define LIST_OPCODE 2
#define MATCH_OPCODE 3
#define ACK_OPCODE 4
#define DENY_OPCODE 5
#define LOGOUT_OPCODE 6
#define ERR_OPCODE 7

struct message{
	uint16_t opcode;
    uint32_t my_ip;
    uint32_t dest_ip; // NULL if opcode != MATCH. In that case 
                      // Server thread just forward MATCH message
                      // and dest_client reply (ACK or DENY)
};