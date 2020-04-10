#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<errno.h>
#include"header/message.h"
#include"header/send.h"
#include"header/receive.h"

#define BUFLEN 1024

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
	printf("BIND SERVER CHILD %d to the port %d: %d\n", num_bind, ntohs(my_addr.sin_port), ret);
	return sd;
}

struct message pack_ack(){

    struct message aux;
    aux.opcode = ACK_OPCODE;
    aux.my_ip = my_addr.sin_addr.s_addr;
    return aux;
}

int handle_request(struct message* aux, struct sockaddr_in *cl_addr,int sd){

    uint16_t opcode = (uint16_t) aux->opcode;   
    printf("opcode: %d\n", opcode);
    switch(opcode){

        case LOGIN_OPCODE:
            printf("Placeholder controllo IP...\n");
            struct message m = pack_ack();
            send_message(&m, cl_addr, sd);
            break;
    }

	return 1;
}

int main(int argc, char* argv[]){

	int ret,sd;
	struct sockaddr_in cl_addr;
	struct message m;	

	char sv_dir[128];

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
	printf("BIND SERVER PADRE alla porta %d: %d\n",ntohs(my_addr.sin_port), ret);
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
            close(sd_child);
		}

		//sleep(7);
	}
    

}