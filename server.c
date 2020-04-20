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
#include "header/send.h"
#include "header/receive.h"
#include "header/list.h"
#include "header/utilityFile.h"

#define BUFLEN 1024

char* filename = "loggedUser.csv";
struct sockaddr_in my_addr, listen_addr;
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

struct sockaddr_in setupAddress(char *ip, int port){
    struct sockaddr_in other_addr;
    memset(&other_addr,0, sizeof(other_addr)); //pulizia
    other_addr.sin_family= AF_INET;
    other_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip , &other_addr.sin_addr);
    return other_addr;
}

int handle_request(struct message* aux, struct sockaddr_in *cl_addr,int sd){

	struct message* aux2;
	struct sockaddr_in dest_cl_address, sv_addr;
    uint16_t opcode = (uint16_t) aux->opcode;   
	char *dest_ip;
	uint16_t dest_port;   
	int ret;
	char str[INET_ADDRSTRLEN];
	int sd_listen = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port

	printf("opcode: %d\n", opcode);

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
			inet_ntop(AF_INET, &(cl_addr->sin_addr), str, INET_ADDRSTRLEN);
			int cl_port = aux->my_listen_port;
			sprintf(buffer,"%d,%s,%d", aux->my_id, str, cl_port);
			append_row(filename, buffer);
            struct message m = pack_ack(aux->my_id);
            send_message(&m, cl_addr, sd);
            break;
		case LIST_OPCODE:
            printf("List request from ID: %d\n", aux->my_id);
            struct message ackList = pack_list_ack(aux->my_id);
            send_message(&ackList, cl_addr, sd);
            break;
		case MATCH_OPCODE:
			printf("%d <--> %d \n", aux->dest_id, ntohs(aux->dest_id));
			dest_ip = get_column_by_id(filename, ntohs(aux->dest_id), 2);
			dest_port = atoi(get_column_by_id(filename, ntohs(aux->dest_id), 3));
			printf("DEST IP: %s\n", dest_ip);
			printf("DEST PORT; %u\n", dest_port);
            
			sd_listen = socket(AF_INET, SOCK_DGRAM, 0);

			//addres creation
			memset(&listen_addr,0, sizeof(listen_addr)); //pulizia
			listen_addr.sin_family= AF_INET;
			listen_addr.sin_port = htons(dest_port);
			//listen_addr.sin_addr.s_addr = INADDR_ANY;
			inet_pton(AF_INET, dest_ip , &listen_addr.sin_addr);

            send_message(aux, &listen_addr, sd_listen);
			printf("waiting reply\n");

			struct message aux_risp;
			int req = recv_message(sd_listen, &aux_risp, (struct sockaddr*)&listen_addr); //3000 receive port and then pass message to others
			if(req!=1){
				printf("Errore (andra' implementato ERR_OPCODE)\n");
				close(sd_listen);
				exit(1);
			}

			//printf("flag: %d \n", (int)aux->flag);

			struct message risp;
			risp.opcode = REPLY_OPCODE;
			risp.dest_ip = dest_ip;
			risp.dest_port = dest_port;
			risp.flag = aux_risp.flag;
			
			
			//printf("source port: %d", ntohl(cl_addr->sin_port));
			//struct sockaddr_in resp_addr = setupOtherAddress("127.0.0.1", ntohl(cl_addr->sin_port));
			//send_message(&aux, &resp_addr, sd);
			send_message(&risp, cl_addr, sd);
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
		int req = recv_message(sd, &m, (struct sockaddr*)&cl_addr); //3000 receive port and then pass message to others
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