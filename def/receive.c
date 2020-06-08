

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
	msg->sign_len = (msg->sign_len)?ntohs(msg->sign_len):0;
	msg->cert_len = (msg->cert_len)?ntohs(msg->cert_len):0;
	msg->pkey_len = (msg->pkey_len)?ntohs(msg->pkey_len):0;
}

int deserialize_message(unsigned char* buffer, struct message *aux){

	uint16_t opcodex, *temp;
	int pos =0;

	memcpy(&opcodex, buffer, sizeof(opcodex));
	//printf("opcode: %d\n", opcodex);
	aux->opcode = opcodex;
	pos+=sizeof(opcodex);
	//printf("aux opcode %d\n", aux->opcode);
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
			for (int i = 0; i < ntohs(aux->nOnlinePlayers); i++){
				aux->onlinePlayers[i] = ntohs(temp[i]);
				pos+= sizeof(uint16_t);
			}
			printf("\n");
			break;
		case LOGOUT_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			break;

		case MATCH_MOVE_OPCODE:
			memcpy(&aux->my_id, buffer+pos, sizeof(aux->my_id));
			pos += sizeof(aux->my_id);
			memcpy(&aux->addColumn, buffer+pos, sizeof(aux->addColumn));
			pos += sizeof(aux->addColumn);
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
		case KEY_OPCODE:
			printf("Sono quiii!\n");
			memcpy(&aux->pkey_len, buffer+pos, sizeof(aux->pkey_len));
			printf("sono qua con pkey-len %d!\n", aux->pkey_len);
			pos += sizeof(aux->pkey_len);
			//char *temp1 = (char *)buffer+pos;
			//printf(temp1[0]);
			printf("pkey len %d\n", aux->pkey_len);
			aux->peerkey = malloc(ntohs(aux->pkey_len)+1); //POSSIBILE ERRORE
			for (uint64_t i = 0; i < ntohs(aux->pkey_len); i++){
				aux->peerkey[i] = (unsigned char)*(buffer+pos);
				//printf("%d,%c,%c", i, *(buffer+pos),aux->peerkey[i]);
				pos+= sizeof(char);
			}
			break;
		case AUTH2_OPCODE:
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			break;
		case AUTH3_OPCODE:
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);
			memcpy(&aux->sign_len, buffer+pos, sizeof(aux->sign_len));
			pos += sizeof(aux->sign_len);
			aux->sign = malloc(ntohs(aux->sign_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->sign_len); i++){
				aux->sign[i] = (unsigned char)*(buffer+pos);
				pos+= sizeof(char);
				//printf("%u", aux->sign[i]);
			}
			break;
		case AUTH4_OPCODE:
			memcpy(&aux->sign_len, buffer+pos, sizeof(aux->sign_len));
			pos += sizeof(aux->sign_len);
			aux->sign = malloc(ntohs(aux->sign_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->sign_len); i++){
				aux->sign[i] = (unsigned char)*(buffer+pos);
				pos+= sizeof(char);
				//printf("%u", aux->sign[i]);
			}
			memcpy(&aux->cert_len, buffer+pos, sizeof(aux->cert_len));
			pos += sizeof(aux->cert_len);
			//printf("\n POS1 %d e DIM CERT LEN %d\n", pos, ntohs(aux->cert_len));
			aux->cert = malloc(ntohs(aux->cert_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->cert_len); i++){
				aux->cert[i] = (unsigned char)*(buffer+pos);
				pos+= 1;
				//printf("%u", aux->cert[i]);
				//printf("%d",pos);
			}
			//printf("sign %d e cert %d\n", aux->sign_len, aux->cert_len);
			break;
		default:
			break;
	}
	toHost(aux);
	return 1;
}

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr){
  	int ret;
  	void *buffer = malloc(MAX_BUFFER_LEN);
  	int buffersize = MAX_BUFFER_LEN;
	socklen_t addrlen = sizeof(struct sockaddr_in);


	//printf("Waiting new message\n");
  	ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
	//printf("New message!!!\n");

	if(ret<0){
		perror("ERRORE recvfrom\n");
		exit(1);		
	}

	// decifra buf (magari con flag)

	ret = deserialize_message(buffer, message);
	return ret;
}
