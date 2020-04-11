

#include "../header/receive.h"

int deserialize_message(char* buffer, struct message *aux){

	uint16_t opcodex, *temp;
	int pos =0;

	memcpy(&opcodex, buffer, sizeof(opcodex));
	//printf("opcode: %d\n", opcodex);
	aux->opcode = opcodex;
	pos+=sizeof(opcodex);

	switch(opcodex){

        case LOGIN_OPCODE:
            memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
            pos += sizeof(aux->my_id);
            break;
		case ACK_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			break;
		case LIST_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			break;
		case ACK_LIST:
			memcpy(&aux->nOnlinePlayers, buffer+pos, sizeof(uint16_t));
			//pos += sizeof(uint16_t);
			//Return the list of online users
			temp = (uint16_t*)buffer+pos;
			for (int i = 0; i < aux->nOnlinePlayers; i++){
				aux->onlinePlayers[i] = temp[i];
				pos+= sizeof(uint16_t);
			}
			printf("\n");
			break;
		case LOGOUT_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
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


	//printf("Waiting new message\n");
  	ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
	//printf("New message!!!\n");
	
	if(ret<0){
		printf("ERRORE recvfrom\n");
		exit(1);		
	}

	ret = deserialize_message(buffer, message);
	return ret;
}
