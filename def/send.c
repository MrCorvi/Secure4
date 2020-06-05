
#include "../header/send.h"

#define MAX_LEN 128

struct message toNet(struct message* msg){

	struct message aux;
	aux.opcode = htons(msg->opcode);
	aux.my_id = htonl(msg->my_id);
	aux.my_listen_port = htons(msg->my_listen_port);
	aux.nOnlinePlayers = htons(msg->nOnlinePlayers); 
	aux.dest_id = htonl(msg->dest_id);
	aux.dest_ip = htonl(msg->dest_ip);
	aux.my_listen_port = htons(msg->my_listen_port);
	aux.dest_port = htons(msg->dest_port);
	aux.flag = htons(msg->flag);
	aux.addColumn = htons(msg->addColumn);
	aux.nonce = htonl(msg->nonce);
	
	return aux;
}

int serialize_message(void* buffer, struct message *msg){

	//printf("Serializzazione messaggio...\n");

	struct message aux = toNet(msg);

	int pos=0, len;
	uint16_t opcode = (uint16_t) msg->opcode;
	uint16_t temp;

	memcpy(buffer+pos, &aux.opcode , 2);
	pos += 2;
	switch(opcode){

		case LOGIN_OPCODE:
            memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));	
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.my_listen_port, sizeof(aux.my_listen_port));
            pos += sizeof(aux.my_listen_port);
			printf("login, buffer contienete: %d, %d e poi %d\n", aux.opcode, aux.my_id, aux.my_listen_port);
			break;
		case ACK_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			break;
		case LIST_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			break;
		case LOGOUT_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			break;
		case ACK_LIST:
			memcpy(buffer+pos, &aux.nOnlinePlayers, sizeof(aux.nOnlinePlayers));
			pos+=sizeof(aux.nOnlinePlayers);

			for (int i = 0; i < msg->nOnlinePlayers; i++){
				temp = htons(msg->onlinePlayers[i]);
				memcpy(buffer+pos, &temp, sizeof(temp));
				pos+= sizeof(temp);
				printf("- %d \n", msg->onlinePlayers[i]);
			}
			break;
		case MATCH_MOVE_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.addColumn, sizeof(aux.addColumn));
			pos+=sizeof(aux.addColumn);
			break;
		case MATCH_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.dest_id, sizeof(aux.dest_id));
			pos+=sizeof(aux.dest_id);
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			break;
		case REPLY_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.dest_id, sizeof(aux.dest_id));
			pos+=sizeof(aux.dest_id);
			memcpy(buffer+pos, &aux.flag, sizeof(aux.flag));
			pos+=sizeof(aux.flag);
			memcpy(buffer+pos, &aux.dest_ip, sizeof(aux.dest_ip));
			pos+=sizeof(aux.dest_ip);
			memcpy(buffer+pos, &aux.dest_port, sizeof(aux.dest_port));
			pos+=sizeof(aux.dest_port);
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			printf("AUX FLAG INVIATO: %u <--> %d\n ", aux.flag, aux.flag );
			break;
		default:
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
		perror("sendto ERROR");
		exit(1);		
	}	

}
