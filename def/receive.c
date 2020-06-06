

#include "../header/receive.h"

void toHost(struct message* msg){

	msg->opcode = (msg->opcode!=0)?ntohs(msg->opcode):0;
	msg->my_id = (msg->my_id!=0)?ntohl(msg->my_id):0;
	msg->my_listen_port = (msg->my_listen_port!=0)?ntohs(msg->my_listen_port):0;
	msg->nOnlinePlayers = (msg->nOnlinePlayers!=0)?ntohs(msg->nOnlinePlayers):0; 
	msg->dest_id = (msg->dest_id!=0)?ntohl(msg->dest_id):0;
	msg->dest_ip = (msg->dest_ip!=0)?ntohl(msg->dest_ip):0;
	msg->dest_port = (msg->dest_port)?ntohs(msg->dest_port):0;
	msg->flag = (msg->flag)?ntohs(msg->flag):0;
	msg->addColumn = (msg->addColumn)?ntohs(msg->addColumn):0;
	msg->nonce = (msg->nonce)?ntohl(msg->nonce):0;
}

int deserialize_message(char* buffer, struct message *aux){

	uint16_t opcodex, *temp;
	int pos =0;

	memcpy(&opcodex, buffer, sizeof(opcodex));
	//printf("opcode: %d\n", opcodex);
	aux->opcode = opcodex;
	pos+=sizeof(opcodex);
	printf("aux opcode %d\n", aux->opcode);
	switch(ntohs(aux->opcode)){

        case LOGIN_OPCODE:
            memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
            pos += sizeof(aux->my_id);
			memcpy(&aux->my_listen_port, buffer+pos, sizeof(aux->my_listen_port));
            pos += sizeof(aux->my_listen_port);
            break;
		case ACK_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			break;
		case LIST_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			break;
		case ACK_LIST:
			memcpy(&aux->nOnlinePlayers, buffer+pos, sizeof(aux->nOnlinePlayers));
			pos += sizeof(aux->nOnlinePlayers);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			//pos += sizeof(aux->nonce);
			
			temp = (uint16_t*)buffer+pos;
			for (int i = 0; i < ntohs(aux->nOnlinePlayers); i++){
				aux->onlinePlayers[i] = ntohs(temp[i]);
				pos+= sizeof(uint16_t);
			}
			//printf("\n");
			break;
		case LOGOUT_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			break;

		case MATCH_MOVE_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->addColumn, buffer+pos, sizeof(aux->addColumn));
			pos += sizeof(aux->addColumn);

			//decipher
			memcpy(&aux->ptLen, buffer+pos, sizeof(aux->ptLen));
			pos += sizeof(aux->ptLen);
			memcpy(&aux->cphtBuffer, buffer+pos, sizeof(aux->cphtBuffer));
			pos += (int) aux->ptLen;
			memcpy(&aux->tagBuffer, buffer+pos, sizeof(aux->tagBuffer));
			pos += 16;
			break;

		case MATCH_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->dest_id, buffer+pos, sizeof(aux->dest_id));
			pos += sizeof(aux->dest_id);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			break;
		case REPLY_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->dest_id, buffer+pos, sizeof(aux->dest_id));
			pos += sizeof(aux->dest_id);
			memcpy(&aux->flag, buffer+pos, sizeof(aux->flag));
			pos += sizeof(aux->flag);
			memcpy(&aux->dest_ip, buffer+pos, sizeof(aux->dest_ip));
			pos += sizeof(aux->dest_ip);
			memcpy(&aux->dest_port, buffer+pos, sizeof(aux->dest_port));
			pos += sizeof(aux->dest_port);
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			printf("AUX FLAG ricevuto: %u <--> %d\n ", aux->flag, aux->flag );
			break;
		default:
			break;
	}
	toHost(aux);
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
		perror("ERRORE recvfrom\n");
		exit(1);		
	}

	ret = deserialize_message(buffer, message);
	printf("recv_message() RICEVO %d E %d\n", message->my_id, message->my_listen_port);
	return ret;
}
