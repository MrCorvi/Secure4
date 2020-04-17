#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include "header/forza4Engine.h"
#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"header/message.h"
#endif
#include "header/send.h"
#include "header/receive.h"
#include "header/list.h"

#define CMD_UNKNOWN 0
#define CMD_HELP 1
#define CMD_LIST 2
#define CMD_MATCH 3
#define CMD_LOGOUT 4
#define CMD_DIRECT_MATCH 10
#define CMD_WAIT_MATCH 11

char *dest_ip;
struct sockaddr_in cl_address, sv_addr;
char* sv_ip;
int sv_port, cl_id, cl2_id;

void print_help(){

	printf("Commands are the following:\n");
	printf("!help --> show all available commands\n");
    printf("!list --> get IPs of all online clients\n");
    printf("!match dest_ip -> request a challenge to the client corresponding to dest_ip\n");
    printf("!battle --> direct match\n");
    printf("!wait --> wait for match request\n");
	printf("!logout --> logout by the server and stop the program\n");
    
}

int get_cmd(){

	char cmd_s[128];
	
    printf("\033[0;32m");
	printf(">  ");
	printf("\033[0m"); 
    if(	fgets(cmd_s, 128, stdin)==NULL){
        printf("Error fgets da gestire. Per ora terminazione forzata\n");
        exit(1);
    } 
    char *p = strchr(cmd_s, '\n');
    if(p){*p='\0';}
    
    // N.B. strncmp() compare only an initial subset CMD_DIRECT_MATCH
    // I have to be sure input is not shorter

	if(strlen(cmd_s)<5){
    	return CMD_UNKNOWN ;
	}

    if(strncmp(cmd_s, "!help",5)==0){
        return CMD_HELP;
    }

    if(strncmp(cmd_s, "!list",5)==0){
        return CMD_LIST;
    }

    if(strncmp(cmd_s, "!wait",5)==0){
        return CMD_WAIT_MATCH;
    }

	if (strlen(cmd_s)<6){
    	return CMD_UNKNOWN;
    }

	
	if(strncmp(cmd_s, "!match",6)==0){
        // read from cmd_s and "fill" variables
        // return filled variables
        // without m is a segmentation error
		int filled = sscanf(cmd_s, "%*s %ms", &dest_ip );		
		if(filled!=1)
			return CMD_UNKNOWN;
		else
			return CMD_MATCH;
	}
	if (strlen(cmd_s)<7)
    	return CMD_UNKNOWN;

    if (strncmp(cmd_s, "!battle",5)==0){
    	return CMD_DIRECT_MATCH ;
    }

	if(strncmp(cmd_s, "!logout",7)==0)
		return CMD_LOGOUT;

	return CMD_UNKNOWN;
}

void pack_login_message(struct message* aux){

	aux->opcode = LOGIN_OPCODE;
    aux->my_id = cl_id;
}

void pack_logout_message(struct message* aux){

	aux->opcode = LOGOUT_OPCODE;
    aux->my_id = cl_id;
}

void pack_match_move_message(struct message* aux, uint8_t column){
    aux->opcode = MATCH_MOVE_OPCODE;
    aux->my_id = cl_id;
    aux->addColumn = column;
}

struct sockaddr_in setupOtherAddress(char *ip, int port){
    struct sockaddr_in other_addr;
    memset(&other_addr,0, sizeof(other_addr)); //pulizia
    other_addr.sin_family= AF_INET;
    other_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip , &other_addr.sin_addr);
    return other_addr;
}

int main(int argc, char* argv[]){

    struct message m, listRequestMessage;
	int sd, opponentPort, secondary_port;
    struct sockaddr_in opponent_addr;

	// argument check
	if(argc < 4){
		printf("Not enough arguments. Try Again\n");
		printf("./client server_ip server_port\n");
		exit(0);
	}

	sv_ip = argv[1];
	sv_port = atoi(argv[2]); 
    cl_id = atoi(argv[3]);
    secondary_port = atoi(argv[4]);
    

    // socket creation
	sd = socket(AF_INET, SOCK_DGRAM,0);	
	if(sd==-1){
		printf("Socket Creation Error: Client Stopping\n");
		exit(1);
	}


    // address creation
    memset(&opponent_addr,0, sizeof(opponent_addr)); // cleaning
    opponent_addr.sin_family= AF_INET;
    opponent_addr.sin_addr.s_addr = INADDR_ANY;
    opponent_addr.sin_port = htons(secondary_port); // host to net

    printf("This client secondary port: %d\n", secondary_port);

    // secondary socket creation
    int secondSd = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
    int ret = bind(secondSd, (struct sockaddr*)&opponent_addr, sizeof(opponent_addr));
    if(ret!=0){
        perror("Binding Error\n");			
        exit(1);			
    }

	// Client address creation
	memset(&cl_address,0, sizeof(cl_address)); // cleaning
	cl_address.sin_family = AF_INET;
	//hostlong from host byte order to network byte order
	cl_address.sin_addr.s_addr = htonl(INADDR_ANY); 

    pack_login_message(&m);
  
    //server address creation
	memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
	sv_addr.sin_family= AF_INET;
	sv_addr.sin_port = htons(sv_port);
	inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

    printf("Send Login request\n");
	send_message(&m, &sv_addr, sd);
    struct message ack_login_m;
    printf("Waiting ACK...\n");
    recv_message(sd, &ack_login_m, (struct sockaddr*)&sv_addr);
    printf("ACK received... Login Completed\n");
    if(ack_login_m.opcode != ACK_OPCODE){
        printf("Login Opcode Error\n");
        exit(1);
    }
    printf("\033[1;32m");
	printf("Welcome to Forza4");
	printf("\033[0m"); 
    printf(": Enjoy with your friends! ");
    print_help();
    while(1){
        int cmd = get_cmd();

        switch(cmd){
            case CMD_UNKNOWN:
                printf("UNKNOWN COMMAND. Type !help to know the possibile ones\n");
                break;
            case CMD_HELP:
                print_help();
                break;
            case CMD_LIST:

                memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                sv_addr.sin_family= AF_INET;
                sv_addr.sin_port = htons(sv_port);
                inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);
                
                pack_list_message(&listRequestMessage, cl_id);
                listRequest(listRequestMessage, sv_addr, sd);
                break;
            case CMD_MATCH:
                printf("placeholder sfida a ip %s\n", dest_ip);
                //forza4Engine();
                break;
            case CMD_LOGOUT:
                pack_logout_message(&m);

                //DA MODULARIZZARE
                //creazione indirizzo server
                memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                sv_addr.sin_family= AF_INET;
                sv_addr.sin_port = htons(sv_port);
                inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

                send_message(&m, &sv_addr, sd);
                struct message ack_logout_m;
                printf("Waiting Logout ACK....\n");
                recv_message(sd, &ack_logout_m, (struct sockaddr*)&sv_addr);
                printf("Logout ACK received... Login Completed\n");
                if(ack_logout_m.opcode != ACK_OPCODE){
                    printf("Logout Opcode Error\n");
                    exit(1);
                }
                return 1;
                break;
            
            case CMD_DIRECT_MATCH:
                printf("ID of the adversary port: ");
                scanf("%d", &opponentPort);
                printf("\n");

                //connect with other user
                opponent_addr = setupOtherAddress("127.0.0.1", opponentPort);

                pack_match_move_message(&m, 0);
                send_message(&m, &opponent_addr, secondSd);

                printf("Waiting for confirm !!!!\n");
                recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);

                forza4Engine("127.0.0.1", opponentPort, sd, secondSd, TRUE);
                break;

            case CMD_WAIT_MATCH:
      
                //connect with other user
                recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);
                printf("Recived Battle request !!!!\n");
                pack_match_move_message(&m, 0);
                send_message(&m, &opponent_addr, secondSd);

                printf("\n%d\n", ntohs(opponent_addr.sin_port));
                forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), sd, secondSd, FALSE);
                break;
            
            default:
                break;

                exit(0);
        }   
    }
    return 1;
}