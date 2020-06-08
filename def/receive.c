

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
	msg->ptLen = (msg->ptLen)?ntohl(msg->ptLen):0;
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
			memcpy(&aux->nonce, buffer+pos, sizeof(aux->nonce));
			pos += sizeof(aux->nonce);

			/*
			//decipher
			memcpy(&aux->ptLen, buffer+pos, sizeof(aux->ptLen));
			pos += sizeof(aux->ptLen);

			aux->cphtBuffer = (unsigned char*)malloc(ntohl(aux->ptLen));
			memcpy(aux->cphtBuffer, buffer+pos, ntohl(aux->ptLen));
			pos += ntohl(aux->ptLen);

    		aux->tagBuffer  = (unsigned char*)malloc(16);
			memcpy(aux->tagBuffer, buffer+pos, 16);
			pos += 16;
			*/
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

			//printf("NONCE : \n");
   			//BIO_dump_fp(stdout, (const char *)buffer, MAX_BUFFER_SIZE + TAG_SIZE + 12);
			printf("AUX FLAG ricevuto: %u <--> %d\n ", aux->flag, aux->flag );
			break;
		default:
			break;
	}
	toHost(aux);
	return 1;
}

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint32_t nonce){
  	int ret;
  	void *buffer = malloc(1 + MAX_BUFFER_SIZE + TAG_SIZE + 12);
  	int buffersize = 1 + MAX_BUFFER_SIZE + TAG_SIZE + 12;
	socklen_t addrlen = sizeof(struct sockaddr_in);


	//printf("Waiting new message\n");
  	ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
	//printf("New message!!!\n");

   	//BIO_dump_fp(stdout, (const char *)buffer, 1 + MAX_BUFFER_SIZE + TAG_SIZE + 12);
	
	u_int8_t isEncr;
	memcpy(&isEncr, buffer, 1);


	if(isEncr != FALSE){

		//create key
		unsigned char key_gem[]= "1234567890123456";
		//unsigned char iv_gcm[] = "123456789012" ;
		unsigned char iv_gcm[12];
		unsigned char *ct, *tag, pt[MAX_BUFFER_SIZE];
		int pos = 1;
		
		//sprintf(iv_gcm, "%-12d", nonce);
		//printf("									iv: |%s|", iv_gcm);

		//printf("Buffer : \n");
   		//BIO_dump_fp(stdout, (const char *)buffer, MAX_BUFFER_SIZE + TAG_SIZE + 12);

		memcpy(iv_gcm, buffer+pos, 12);
		pos += 12;

		ct = (unsigned char*)malloc(MAX_BUFFER_SIZE);
		memcpy(ct, buffer+pos, MAX_BUFFER_SIZE);
		pos += MAX_BUFFER_SIZE;

		tag  = (unsigned char*)malloc(TAG_SIZE);
		memcpy(tag, buffer+pos, TAG_SIZE);
		pos += TAG_SIZE;

		/*
		printf("CypherText: \n");
		BIO_dump_fp(stdout, (const char *)ct, MAX_BUFFER_SIZE);
		printf("Tag: \n");
		BIO_dump_fp(stdout, (const char *)ct, TAG_SIZE);
		*/

		symDecrypt(pt, MAX_BUFFER_SIZE, key_gem, iv_gcm, ct, tag);

		memcpy(buffer, pt, MAX_BUFFER_SIZE);

		free(ct);
		free(tag);
	}
	
	
	if(ret<0){
		perror("ERRORE recvfrom\n");
		exit(1);		
	}

	ret = deserialize_message(buffer, message);
	//printf("recv_message() RICEVO %d E %d\n", message->my_id, message->my_listen_port);
	return ret;
}
