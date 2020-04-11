
#include "../header/send.h"

#define MAX_LEN 128

int serialize_message(void* buffer, struct message *aux){

	//printf("Serializzazione messaggio...\n");

	int pos=0, len;
	uint16_t opcode = (uint16_t) aux->opcode;

	memcpy(buffer+pos, &opcode , 2);
	pos += 2;

	switch(opcode){

		case LOGIN_OPCODE:
            memcpy(buffer+pos, &aux->my_id, sizeof(aux->my_id));	
			pos+=sizeof(aux->my_id);
			break;
		case ACK_OPCODE:
			memcpy(buffer+pos, &aux->my_id, sizeof(aux->my_id));
			pos+=sizeof(aux->my_id);
			break;
		case LIST_OPCODE:
			memcpy(buffer+pos, &aux->my_id, sizeof(aux->my_id));
			pos+=sizeof(aux->my_id);
			break;
		case LOGOUT_OPCODE:
			memcpy(buffer+pos, &aux->my_id, sizeof(aux->my_id));
			pos+=sizeof(aux->my_id);
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

	printf("sending %d\n", m->opcode);
	ret = sendto(socket, buf, len , 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));	
	if(ret<0){
		printf("sendto ERROR");
		exit(1);		
	}	

}
