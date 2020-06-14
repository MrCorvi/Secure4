

#include "../header/receive.h"



//create key
unsigned char key_gem_recive[]= "123456789012345678901234567890123456789012345678901234567890123456";
int isServerRecive = FALSE;
char filenameReciver[200];

void setKeyFilename(char *fn){
	sprintf(filenameReciver, "../%s", fn);
}

void chaneKeyReciver(unsigned char *newKey, int size){
	memcpy(key_gem_recive, newKey, size);
	printf("New key seted up: \n");
    BIO_dump_fp(stdout, (const char *)key_gem_recive, 17);
}


void setIsServerReciver(){
	isServerRecive = TRUE;
	//printf("dknwndwndbwndnwlkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n");
}


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
	msg->ptLen = (msg->ptLen)?ntohl(msg->ptLen):0;
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

			memcpy(&aux->pkey_len, buffer+pos, sizeof(aux->pkey_len));
			pos += sizeof(aux->pkey_len);

			//printf("recived key of length: %d  %d", aux->pkey_len, ntohs(aux->pkey_len));

			aux->pubKey = (unsigned char *)malloc(aux->pkey_len);
			char *pk = (unsigned char*)buffer+pos;

			//printf("\n\n%d\nChiave ricevuta:\n", ntohs(aux->pkey_len));
			for (uint16_t i = 0; i < ntohs(aux->pkey_len); i++){
				aux->pubKey[i] = pk[i];
				//printf("%c",pk[i]);
				pos+= sizeof(unsigned char);
			}
			//printf("\n");

			//printf("NONCE : \n");
   			//BIO_dump_fp(stdout, (const char *)buffer, MAX_BUFFER_SIZE + TAG_SIZE + 12);
			//printf("AUX FLAG ricevuto: %u <--> %d\n ", aux->flag, aux->flag );
			break;
		case KEY_OPCODE:
			//printf("Sono quiii!\n");
			memcpy(&aux->pkey_len, buffer+pos, sizeof(aux->pkey_len));
			//printf("sono qua con pkey-len %d!\n", aux->pkey_len);
			pos += sizeof(aux->pkey_len);
			//char *temp1 = (char *)buffer+pos;
			//printf(temp1[0]);
			//printf("pkey len %d\n", aux->pkey_len);
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

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint32_t nonce){
  	int ret;
	uint32_t senderId;
  	void *buffer = malloc(1 + sizeof(senderId) + MAX_BUFFER_SIZE + TAG_SIZE + 12);
  	int buffersize = 1 + MAX_BUFFER_SIZE + TAG_SIZE + 12;
	socklen_t addrlen = sizeof(struct sockaddr_in);


	//printf("Waiting new message\n");
  	ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
	//printf("New message!!!\n");

   	//BIO_dump_fp(stdout, (const char *)buffer, 64);
	
	u_int8_t isEncr;
	memcpy(&isEncr, buffer, 1);


	if(isEncr != FALSE){

		//unsigned char iv_gcm[] = "123456789012" ;
		unsigned char iv_gcm[12];
		unsigned char *ct, *tag, pt[MAX_BUFFER_SIZE];
		int pos = 1;
		
		//sprintf(iv_gcm, "%-12d", nonce);
		//printf("									iv: |%s|", iv_gcm);

		//printf("Buffer : \n");
   		//BIO_dump_fp(stdout, (const char *)buffer, MAX_BUFFER_SIZE + TAG_SIZE + 12);

		memcpy(&senderId, buffer+pos, sizeof(senderId));
		pos += sizeof(senderId);
		printf("Id ricevuto :%d\n", senderId);

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

		//get the sender key
		unsigned char k[300];
		strcpy(k, key_gem_recive);
		if(isServerRecive == TRUE){
			printf("Sono in un server !!!!!!!!!!\n");
			get_buf_column_by_id("loggedUser.csv", (int)senderId, 5, k);
			printf("R-----------------------------------------------------------------------------------------\n");
		}
		printf("%s\n", k);
		sprintf(symKey, (char*)k);

		symDecrypt(pt, MAX_BUFFER_SIZE, k, iv_gcm, ct, tag);

		//printf("PlainText: \n");
		//BIO_dump_fp(stdout, (const char *)pt, 200);

		memcpy(buffer, pt, MAX_BUFFER_SIZE);

		free(ct);
		free(tag);
	}
	
	
	if(ret<0){
		perror("ERRORE recvfrom\n");
		exit(1);		
	}

	// decifra buf (magari con flag)

	ret = deserialize_message(buffer, message);
	return ret;
}
