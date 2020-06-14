
#include<stdint.h> 

#define LOGIN_OPCODE 1 //a.ka. AUTH1_OPCODE
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
#define KEY_OPCODE 12
#define AUTH2_OPCODE 13
#define AUTH3_OPCODE 14
#define AUTH4_OPCODE 15

#define MAX_USERS 2000

#define TRUE 1
#define FALSE 0

#define MAX_BUFFER_SIZE 4096
#define TAG_SIZE 16
#define SECRET_SIZE 64
#define DIGEST_SIZE 32
#define SIGN_SIZE 64

#define TIMEOUT_TIME 60

struct message{
	uint16_t opcode;
    uint32_t my_id;
    uint16_t onlinePlayers[MAX_USERS];
    uint16_t nOnlinePlayers;
    uint32_t dest_id; // NULL if opcode != MATCH. In that case 
                      // Server thread just forward MATCH message
                      // and dest_client reply (ACK or DENY)
    uint16_t addColumn;//Used in game to specifie, in game, the Column where to add the disk
    uint32_t dest_ip;
    uint16_t my_listen_port;
    uint16_t dest_port;
    uint16_t column; 
    uint16_t flag; // 1 accept 0 deny
    uint32_t nonce;
    char* peerkey;
    uint16_t pkey_len;
    unsigned char* sign;
    uint16_t sign_len;
    unsigned char* cert;
    uint16_t cert_len;
    unsigned char *cphtBuffer;
    int ptLen; //plain text length
    unsigned char *tagBuffer;
    unsigned char *pubKey;
};