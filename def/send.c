
#include "../header/send.h"

#define MAX_BUFFER_SIZE 128

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
	aux.ptLen = htonl(msg->ptLen);
	
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
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			break;
		case LIST_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			break;
		case LOGOUT_OPCODE:
			memcpy(buffer+pos, &aux.my_id, sizeof(aux.my_id));
			pos+=sizeof(aux.my_id);
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			break;
		case ACK_LIST:
			memcpy(buffer+pos, &aux.nOnlinePlayers, sizeof(aux.nOnlinePlayers));
			pos+=sizeof(aux.nOnlinePlayers);
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);

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
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
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


void send_message(struct message *m, struct sockaddr_in * dest_addr,int socket, int encrypt){

	void *buf;
	buf = malloc(MAX_BUFFER_SIZE + TAG_SIZE);	
	int ret;


	// packet creation
	//printf("ptLen: %d\n", m->ptLen); 
	int len = serialize_message(buf, m);

	if(encrypt == TRUE){
		//create key
		unsigned char key_gem[]= "1234567890123456";
		//unsigned char iv_gcm[] = "123456789012" ;
		unsigned char iv_gcm[13];
		
		//Cypher
		unsigned char *ct   = (unsigned char*)malloc(MAX_BUFFER_SIZE);	
		unsigned char *tag  = (unsigned char*)malloc(TAG_SIZE);
		unsigned char pt[MAX_BUFFER_SIZE];
		int ptLen = MAX_BUFFER_SIZE;
		int pos = 0;

		sprintf(iv_gcm, "%-12d", m->nonce - 1);
		printf("									iv: |%s|", iv_gcm);

		memcpy(pt, buf, MAX_BUFFER_SIZE);

		symEncrypt(pt, MAX_BUFFER_SIZE, key_gem, iv_gcm, ct, tag);

		memcpy(buf+pos, (const char *) ct, MAX_BUFFER_SIZE);
		pos+= MAX_BUFFER_SIZE;

		memcpy(buf+pos, (const char *) tag, TAG_SIZE);
		pos+= 16;


		free(ct);
		free(tag);
	}

	ret = sendto(socket, buf, len , 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));	
	if(ret<0){
		perror("sendto ERROR");
		exit(1);		
	}	

}
