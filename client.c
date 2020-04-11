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

char *dest_ip;
struct sockaddr_in cl_address, sv_addr;
char* sv_ip;
int sv_port;

void print_help(){

	printf("Commands are the following:\n");
	printf("!help --> show all available commands\n");
    printf("!list --> get IPs of all online clients\n");
    printf("!match dest_ip -> request a challenge to the client corresponding to dest_ip\n");
	printf("!logout --> logout by the server and stop the program\n");

}

int get_cmd(){

	char cmd_s[128];
	
	printf(">  ");
    if(	fgets(cmd_s, 128, stdin)==NULL){
        printf("Error fgets da gestire. Per ora terminazione forzata\n");
        exit(1);
    } 
    char *p = strchr(cmd_s, '\n');
    if(p){*p='\0';}
    
    // N.B. strncmp() compare only an initial subset
    // I have to be sure input is not shorter

	if(strlen(cmd_s)<5){
    	return CMD_UNKNOWN ;
	}

    if(strncmp(cmd_s, "!help",5)==0)
        return CMD_HELP;

    if(strncmp(cmd_s, "!list",5)==0)
        return CMD_LIST;

	if (strlen(cmd_s)<6)
    	return CMD_UNKNOWN ;
	
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

	if(strncmp(cmd_s, "!logout",7)==0)
		return CMD_LOGOUT;

	return CMD_UNKNOWN;
}

void pack_login_message(struct message* aux){

	aux->opcode = LOGIN_OPCODE;
    aux->my_ip = cl_address.sin_addr.s_addr;
}

int main(int argc, char* argv[]){

    struct message m, listRequestMessage;
	int sd;

	// argument check
	if(argc < 3){
		printf("Not enough arguments. Try Again\n");
		printf("./client server_ip server_port\n");
		exit(0);
	}

	sv_ip = argv[1];
	sv_port = atoi(argv[2]); 

    // socket creation
	sd = socket(AF_INET, SOCK_DGRAM,0);	
	if(sd==-1){
		printf("Socket Creation Error: Client Stopping\n");
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
    printf("Welcome to Forza4 : Enjoy with your friends! ");
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
                
                //printf("placeholder list\n");
                pack_list_message(&listRequestMessage);
                //printf("%d\n", listRequestMessage.opcode);
                listRequest(listRequestMessage, sv_addr, sd);

<<<<<<< HEAD
                /*
=======
                	//creazione indirizzo server
                    memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                    sv_addr.sin_family= AF_INET;
                    sv_addr.sin_port = htons(sv_port);
                    inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

>>>>>>> origin/loginAndLogout
                send_message(&m, &sv_addr, sd);
                struct message ack_login_m;
                printf("Waiting ACK...\n");
                recv_message(sd, &ack_login_m, (struct sockaddr*)&sv_addr);
                printf("ACK received... Login Completed\n");
                if(ack_login_m.opcode != ACK_OPCODE){
                    printf("Login Opcode Error\n");
                    exit(1);
                }*/
                break;
            case CMD_MATCH:
                printf("placeholder sfida a ip %s\n", dest_ip);
                forza4Engine();
                break;
            case CMD_LOGOUT:
                printf("placeholder logout\n");
                exit(0);
        }   
    }
    return 1;
}