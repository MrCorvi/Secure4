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

uint16_t dest_id;
struct sockaddr_in cl_address, cl_listen_addr, sv_addr;
char* sv_ip;
int sv_port, cl_id, cl2_id, cl_listen_port;

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
		int filled = sscanf(cmd_s, "%*s %u\n", (unsigned int *)&dest_id );	
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
    aux->my_listen_port = cl_listen_port;
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

void pack_reply_message(struct message* aux, uint16_t flag, uint16_t dest_id_aux){

    aux->opcode = REPLY_OPCODE;
    aux->my_id = cl_id;
    aux->dest_id = dest_id_aux;
    aux->flag = flag;
}

void pack_match_message(struct message* aux){

    aux->opcode = MATCH_OPCODE;
    aux->my_id = cl_id;
    aux->dest_id = htons(dest_id);
    printf("Dest id pack match: %u, %u", dest_id, aux->dest_id);

}

int main(int argc, char* argv[]){

    struct message m, listRequestMessage;
	int sd, opponentPort, secondary_port;
    struct sockaddr_in opponent_addr;

	// argument check
	if(argc < 4){
		printf("Not enough arguments. Try Again\n");
		printf("./client server_ip your_id server_port\n");
		exit(0);
	}

	sv_ip = argv[1];
	sv_port = atoi(argv[2]); 
    cl_id = atoi(argv[3]);
    secondary_port = atoi(argv[4]);
    
    cl_listen_port = (argc==5)? atoi(argv[4]): sv_port+100;
    cl_listen_port = secondary_port;

    pid_t pid;

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
    cl_address.sin_port = htons(sv_port);
    pack_login_message(&m);
    printf("PORTA: %d\n", cl_listen_port);

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

    pid = fork();
	if(pid==-1){
		printf("Fork Error\n");
		exit(1);		
	}	
	if(pid==0){ // child process

        while(1){
            struct message match_m;
            struct sockaddr_in sv_addr_listen;
            char cmd_s[128];

            //addres creation
            memset(&cl_listen_addr,0, sizeof(cl_listen_addr)); //pulizia
            cl_listen_addr.sin_family= AF_INET;
            cl_listen_addr.sin_addr.s_addr = INADDR_ANY;
            cl_listen_addr.sin_port = htons(cl_listen_port);

            int sd = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
            //int ret = bind(sd, (struct sockaddr*)&cl_listen_addr, sizeof(cl_listen_addr));
            if(ret!=0){
			    perror("Binding Error\n");			
			    exit(1);			
	        }
            recv_message(secondSd, &match_m, (struct sockaddr*)&sv_addr_listen);

            if(match_m.opcode == ACCEPT_OPCODE){
                printf("Sfida accettata (child thread)\n");
            }else if(match_m.opcode == MATCH_OPCODE){
                
                struct message reply_m;

                printf("Sei stato sfidato da: %d. Accetti? [y/n]", match_m.my_id);
                printf("\033[0;32m");
                printf(">  ");
                printf("\033[0m"); 
                if(	fgets(cmd_s, 128, stdin)==NULL){
                    printf("Error fgets da gestire. Per ora terminazione forzata\n");
                    exit(1);
                } 
                printf("CMD_S %s\n", cmd_s);
                if(strncmp(cmd_s,"y",1)==0){
                    printf("Hai accettato\n");
                    pack_reply_message(&reply_m, 1, match_m.my_id);
                }
                else{
                    printf("Hai rifiutato\n");
                    pack_reply_message(&reply_m, 0, match_m.my_id);
                }
                
                //sv_addr_listen = setupOtherAddress("127.0.0.1", sv_port);
                send_message(&reply_m, &sv_addr_listen, secondSd);

                if(strncmp(cmd_s,"y",1)==0){
                    printf("Waiting for Battle request...\n");
                    recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);
                    printf("Recived Battle request !!!!\n");
                    pack_match_move_message(&m, 0);
                    send_message(&m, &opponent_addr, secondSd);

                    printf("\n%d\n", ntohs(opponent_addr.sin_port));
                    forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), sd, secondSd, FALSE);
                }

                close(sd);
            }
            else 
                printf("Errore OPCODE da gestire\n");
        }
	}
    else{
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

                    memset(&sv_addr,0, sizeof(sv_addr)); //pu
                    sv_addr.sin_family= AF_INET;
                    sv_addr.sin_port = htons(sv_port);
                    inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);
                    
                    //printf("placeholder list\n");
                    pack_list_message(&listRequestMessage, cl_id);
                    listRequest(listRequestMessage, sv_addr, sd);
                    break;
                case CMD_MATCH:
                    memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                    sv_addr.sin_family= AF_INET;
                    sv_addr.sin_port = htons(sv_port);
                    inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

                    pack_match_message(&m);

                    send_message(&m, &sv_addr, sd);
                    struct message ack_match_m;
                    printf("Waiting Match ACK....\n");
                    
                    recv_message(sd, &ack_match_m, (struct sockaddr*)&sv_addr);
                    int esito = (ack_match_m.flag==1)?ACCEPT_OPCODE:DENY_OPCODE;
                    printf("ACK Match received... Esito\n");
                    if(esito== DENY_OPCODE){
                        printf("Partita rifiutata (main thread)\n");
                    }
                    else if(esito == ACCEPT_OPCODE){
                        printf("Partita accettata (main thread)\n");
                        opponent_addr = setupOtherAddress("127.0.0.1", ack_match_m.dest_port);

                        pack_match_move_message(&m, 0);
                        send_message(&m, &opponent_addr, secondSd);

                        printf("Waiting for confirm !!!!\n");
                        recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);

                        forza4Engine("127.0.0.1", opponentPort, sd, secondSd, TRUE);
                    }
                    else{
                        printf("OPCODE Error da gestire\n");
                    }
                    
                    //forza4Engine();
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
                    printf("Waiting for Battle request...\n");
                    recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);
                    printf("Recived Battle request !!!!\n");
                    pack_match_move_message(&m, 0);
                    send_message(&m, &opponent_addr, secondSd);

                    printf("\n%d\n", ntohs(opponent_addr.sin_port));
                    forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), sd, secondSd, FALSE);
                    break;

                case CMD_LOGOUT:

                    //DA MODULARIZZARE
                    //creazione indirizzo server
                    memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                    sv_addr.sin_family= AF_INET;
                    sv_addr.sin_port = htons(sv_port);
                    inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

                    pack_logout_message(&m);

                    send_message(&m, &sv_addr, sd);
                    struct message ack_logout_m;
                    printf("Waiting Logout ACK....\n");
                    recv_message(sd, &ack_logout_m, (struct sockaddr*)&sv_addr);
                    printf("Logout ACK received... Login Completed\n");
                    if(ack_logout_m.opcode != ACK_OPCODE){
                        printf("Logout Opcode Error: %d\n", ack_logout_m.opcode);
                        exit(1);
                    }
                    exit(0);
            }   
        }
    }
    return 1;
}