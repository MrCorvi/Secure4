

#include "../header/receive.h"

int deserialize_message(char* buffer, struct message *aux){

	uint16_t opcodex;
	int pos =0;

	memcpy(&opcodex, buffer, sizeof(opcodex));
	aux->opcode = opcodex;
	pos+=sizeof(opcodex);

	switch(opcodex){

        case LOGIN_OPCODE:
            memcpy(&aux->my_ip, buffer+pos, sizeof(aux->my_ip));
            pos += sizeof(aux->my_ip);
            break;
		case ACK_OPCODE:
			memcpy(&aux->my_ip, buffer+pos, sizeof(aux->my_ip));
			pos += sizeof(aux->my_ip);
			break;
		case LIST_OPCODE:
			memcpy(&aux->id, buffer+pos, sizeof(aux->id));
			pos += sizeof(aux->my_ip);
			break;
		default:
			break;
	}
	return 1;
}

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr){
  	int ret;
  	void *buffer = malloc(MAX_BUFFER_SIZE);
  	int buffersize = MAX_BUFFER_SIZE;
	socklen_t addrlen = sizeof(struct sockaddr_in);


<<<<<<< HEAD
	//printf("Waiting new message\n");
=======
	printf("Waiting new message at socket %d\n", socket);
>>>>>>> origin/loginAndLogout
  	ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
	//printf("New message!!!\n");
	
	if(ret<0){
		printf("ERRORE recvfrom\n");
		exit(1);		
	}

	ret = deserialize_message(buffer, message);
	return ret;
}
