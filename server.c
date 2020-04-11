#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#ifndef MESSAGE_H
	#define MESSAGE_H
	#include "header/message.h"
#endif
<<<<<<< HEAD
#include"header/send.h"
#include"header/receive.h"
#include"header/list.h"
#include"header/utilityFile.h"
=======
#include "header/send.h"
#include "header/receive.h"
#include "header/list.h"
#include "header/utilityFile.h"
>>>>>>> origin/master

#define BUFLEN 1024

char* filename = "loggedUser.csv";
struct sockaddr_in my_addr;
int num_bind =0;
int sv_port;

int socket_creation(){
	struct sockaddr_in my_addr;
	int sd = socket(AF_INET, SOCK_DGRAM, 0); // just socket creation (not yet IP or port)

	//addres creation
	memset(&my_addr,0, sizeof(my_addr)); //pulizia
	my_addr.sin_family= AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(sv_port+num_bind);

	int ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret!=0){
  		printf("Errore Binding: %s\n", strerror(errno));		
		exit(1);
	}
	printf("\033[1;32m");
	printf("BIND SERVER ");
	printf("\033[0m"); 
	printf("CHILD %d to the port %d: %d\n", num_bind, ntohs(my_addr.sin_port), ret);
	return sd;
}

struct message pack_ack(uint32_t id){

    struct message aux;
    aux.opcode = ACK_OPCODE;
    aux.my_id = id;
    return aux;
}

struct message pack_list_ack(){
    struct message aux;
	uint16_t len;
    aux.opcode = ACK_LIST;
	get_ID_column("loggedUser.csv", &len, aux.onlinePlayers);
	aux.nOnlinePlayers = len;
    /*for (int i = 0; i < aux.nOnlinePlayers; i++){
		printf("- %d \n", aux.onlinePlayers[i]);
	}*/
	
	/*
	aux.nOnlinePlayers = 3;
	aux.onlinePlayers[0] = 100;
    aux.onlinePlayers[1] = 150;
	aux.onlinePlayers[2] = 200;*/
	return aux;
}

int handle_request(struct message* aux, struct sockaddr_in *cl_addr,int sd){

    uint16_t opcode = (uint16_t) aux->opcode;   
    printf("opcode: %d\n", opcode);
	int ret;

    switch(opcode){

        case LOGIN_OPCODE:
            printf("Placeholder controllo ID.....\n");
			
			int ret = get_row_by_id(filename, aux->my_id);
			printf("row : %d", ret);
			if(ret!=-1){
				printf("ERRORE GIA' LOGGATO, da gestire con Err pack");
				// per ora inserisce comunque per agevolare testing
			}
			char buffer[1024];
			long cl_ip = cl_addr->sin_addr.s_addr;
			int cl_port = cl_addr->sin_port;
			sprintf(buffer,"%d,%ld,%d", aux->my_id, cl_ip, cl_port);
			append_row(filename, buffer);
            struct message m = pack_ack(aux->my_id);
            send_message(&m, cl_addr, sd);
            break;
		case LIST_OPCODE:
<<<<<<< HEAD
            printf("List request from ID %d\n", aux->id);
            struct message ackList = pack_list_ack();
=======
            printf("List request from ID: %d\n", aux->my_id);
            struct message ackList = pack_ack(aux->my_id);
>>>>>>> origin/master
            send_message(&ackList, cl_addr, sd);
            break;
		case LOGOUT_OPCODE:
			//look at .csv if correct id
			ret = get_row_by_id(filename,aux->my_id);
			//if not pack err
			if(ret==-1){
				printf("ID non presente!\n");
				return -1;
			}
			printf("rimuovo riga %d \n", ret);
			remove_row(filename, ret);
			printf("Riga rimossa!\n");
			struct message ackLogout = pack_ack(aux->my_id);
            send_message(&ackLogout, cl_addr, sd);
		default:
			break;
    }

	return 1;
}

int main(int argc, char* argv[]){

	int ret,sd;
	struct sockaddr_in cl_addr;
	struct message m;	

	// argument check
	if(argc < 2){
		printf("Not enough arguments. Try Again\n");
		printf("./server listen_server_port\n");
		exit(0);
	}
	sv_port = atoi(argv[1]); 
			
	// address creation
	memset(&my_addr,0, sizeof(my_addr)); // cleaning
	my_addr.sin_family= AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(sv_port); // host to net

	// main socket creation
	sd = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
	ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret!=0){
			perror("Binding Error\n");			
			exit(1);			
	}
	printf("\033[1;32m");
	printf("BIND SERVER ");
	printf("\033[0m"); 
	printf("PADRE alla porta %d: %d\n",ntohs(my_addr.sin_port), ret);
	while(1){		

		pid_t pid;
		int req = recv_message(sd, &m, (struct sockaddr*)&cl_addr); 
		if(req!=1){
            printf("Errore (andra' implementato ERR_OPCODE)\n");
			close(sd);
			exit(1);
		}
		pid = fork();
		num_bind++;
		if(pid==-1){
			printf("Fork Error\n");
			exit(1);		
		}	
		if(pid==0){ // child process
			
			//sleep(5);	
			int sd_child = socket_creation();	
		
           	ret = handle_request( &m, &cl_addr, sd_child);
			printf("End Message handling\n");
            close(sd_child);
			exit(0);
		}

		//sleep(7);
	}
    

}