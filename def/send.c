
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include"../header/message.h"

#define MAX_LEN 128

int serialize_message(void* buffer, struct message *aux){

	//printf("Serializzazione messaggio...\n");

	int pos=0, len;
	uint16_t opcode = (uint16_t) aux->opcode;

	memcpy(buffer+pos, &opcode , 2);
	pos += 2;

	switch(opcode){

		case LOGIN_OPCODE:
            memcpy(buffer+pos, &aux->my_ip, sizeof(aux->my_ip));	
			pos+=sizeof(aux->my_ip);
			break;
		case ACK_OPCODE:
			memcpy(buffer+pos, &aux->my_ip, sizeof(aux->my_ip));
			pos+=sizeof(aux->my_ip);
			break;

	}

	return pos;
}


void send_message(struct message *m, struct sockaddr_in * dest_addr,int socket){

	void *buf;
	buf = malloc(MAX_LEN);	
	int ret;

	// packet creation
	int len = serialize_message(buf, m);

	ret = sendto(socket, buf, len , 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));	
	if(ret<0){
		printf("sendto ERROR");
		exit(1);		
	}	

}