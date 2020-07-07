

#include "../header/receive.h"



//create key
unsigned char key_gem_recive[]= "123456789012345678901234567890123456789012345678901234567890123456";
unsigned char key_client[]= "123456789012345678901234567890123456789012345678901234567890123456";
int isServerRecive = FALSE;
char filenameReciver[200];
int isAlarmFree = FALSE;
int exitOnError = TRUE;
int sdAux;

void setKeyFilename(char *fn){
	sprintf(filenameReciver, "../%s", fn);
}

void chaneKeyReciver(unsigned char *newKey, int size){
	memcpy(key_gem_recive, newKey, size);
}

void changeKeyClientReciver(unsigned char *newKey, int size){
	memcpy(key_client, newKey, size);
}

int getEncMode(uint16_t opcode){

  if(opcode<1 || opcode>16) return -1;
  switch(opcode){
    case LOGIN_OPCODE: return 0;
    case AUTH2_OPCODE: return 0;
    case AUTH3_OPCODE: return 0;
    case AUTH4_OPCODE: return 0;
    case KEY_OPCODE: return 0;
    default:
      return 1;
  }
}


int timeout = 0;
void  ALARMhandler(int sig){
	signal(SIGALRM, SIG_IGN);          // ignore this signal       
	timeout=1;  
	printf("ciaooone e chiuso sd !\n");
	close(sdAux);
	signal(SIGALRM, ALARMhandler);
	if(exitOnError){
		perror("TIMOUT EXIT\n");
		killpg(getpgrp(), SIGKILL); 
		exit(1);		
	}
}

void setIsServerReciver(){
	isServerRecive = TRUE;
	//printf("dknwndwndbwndnwlkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\n");
}

void setIsAlarmfree(int flag){
	isAlarmFree = flag;
}

void setExitOnError(int flag){
	exitOnError = flag;
}

int notBufferOverflow = TRUE;

int checkPos(int *pos, int inc){
	if(notBufferOverflow == FALSE)
		return 0;
	
	if((*pos + inc) > MAX_BUFFER_SIZE){
		notBufferOverflow = FALSE;
		return 0;
	}

	return inc;
}

void incPos(int *pos, int inc){
	if(notBufferOverflow == FALSE)
		return;
	
	if((*pos + inc) > MAX_BUFFER_SIZE){
		notBufferOverflow = FALSE;
		return;
	}
	
	*pos += inc;
}


void toHost(struct message* msg){

	msg->opcode = (msg->opcode!=0)?ntohs(msg->opcode):0;
	msg->my_id = (msg->my_id!=0)?ntohl(msg->my_id):0;
	msg->my_listen_port = (msg->my_listen_port!=0)?ntohs(msg->my_listen_port):0;
	msg->third_port = (msg->third_port!=0)?ntohs(msg->third_port):0;
	msg->nOnlinePlayers = (msg->nOnlinePlayers!=0)?ntohs(msg->nOnlinePlayers):0; 
	msg->dest_id = (msg->dest_id!=0)?ntohl(msg->dest_id):0;
	msg->dest_ip = (msg->dest_ip!=0)?ntohl(msg->dest_ip):0;
	msg->dest_port = (msg->dest_port)?ntohs(msg->dest_port):0;
	msg->flag = (msg->flag)?ntohs(msg->flag):0;
	msg->addColumn = (msg->addColumn)?ntohs(msg->addColumn):0;
	//msg->nonce = (msg->nonce)?ntohl(msg->nonce):0;
	msg->nonce = (msg->nonce)?__bswap_64(msg->nonce):0;
	msg->sign_len = (msg->sign_len)?ntohs(msg->sign_len):0;
	msg->cert_len = (msg->cert_len)?ntohs(msg->cert_len):0;
	msg->pkey_len = (msg->pkey_len)?ntohs(msg->pkey_len):0;
	msg->ptLen = (msg->ptLen)?ntohl(msg->ptLen):0;
}

int deserialize_message(unsigned char* buffer, struct message *aux, uint8_t isEncr){

	uint16_t opcodex, *temp;
	int pos =0;

	memcpy(&opcodex, buffer, sizeof(opcodex));
	//printf("opcode: %d\n", opcodex);
	aux->opcode = opcodex;
	pos+=sizeof(opcodex);
	//printf("get mode %d %d %d\n",ntohs(aux->opcode),getEncMode(ntohs(aux->opcode)),isEncr);
	if(getEncMode(ntohs(aux->opcode))!=isEncr) return -1;
	//printf("aux opcode %d\n", aux->opcode);
	switch(ntohs(aux->opcode)){

        case LOGIN_OPCODE:
            memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->my_listen_port, buffer+pos, checkPos(&pos, sizeof(aux->my_listen_port)));
			incPos(&pos, sizeof(aux->my_listen_port));
			memcpy(&aux->third_port, buffer+pos, checkPos(&pos, sizeof(aux->third_port)));
			incPos(&pos, sizeof(aux->third_port));
            break;
		case ACK_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;
		case LIST_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;
		case ACK_LIST:
			memcpy(&aux->nOnlinePlayers, buffer+pos, checkPos(&pos, sizeof(aux->nOnlinePlayers)));
			incPos(&pos, sizeof(aux->nOnlinePlayers));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			//pos += sizeof(aux->nonce));
			incPos(&pos, sizeof(aux->nonce));
			//temp = (uint16_t*)buffer+pos;
			for (int i = 0; i < ntohs(aux->nOnlinePlayers); i++){
				aux->onlinePlayers[i] = *((uint16_t*)(buffer+pos));
				//printf("+ %x     %d\n", temp[i], pos);
				incPos(&pos, sizeof(aux->onlinePlayers[i]));
			}
			//printf("LIST: \n");
			//BIO_dump_fp(stdout, (const char *)buffer, 30);
			//printf("\n");
			break;
		case LOGOUT_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;

		case MATCH_MOVE_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->addColumn, buffer+pos, checkPos(&pos, sizeof(aux->addColumn)));
			incPos(&pos, sizeof(aux->addColumn));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;

		case MATCH_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->dest_id, buffer+pos, checkPos(&pos, sizeof(aux->dest_id)));
			incPos(&pos, sizeof(aux->dest_id));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;
		case REPLY_OPCODE:
			memcpy(&aux->my_id, buffer+pos, checkPos(&pos, sizeof(aux->my_id)));
			incPos(&pos, sizeof(aux->my_id));
			memcpy(&aux->dest_id, buffer+pos, checkPos(&pos, sizeof(aux->dest_id)));
			incPos(&pos, sizeof(aux->dest_id));
			memcpy(&aux->flag, buffer+pos, checkPos(&pos, sizeof(aux->flag)));
			incPos(&pos, sizeof(aux->flag));
			memcpy(&aux->dest_ip, buffer+pos, checkPos(&pos, sizeof(aux->dest_ip)));
			incPos(&pos, sizeof(aux->dest_ip));
			memcpy(&aux->dest_port, buffer+pos, checkPos(&pos, sizeof(aux->dest_port)));
			incPos(&pos, sizeof(aux->dest_port));
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));

			memcpy(&aux->pkey_len, buffer+pos, checkPos(&pos, sizeof(aux->pkey_len)));
			incPos(&pos, sizeof(aux->pkey_len));

			//printf("recived key of length: %d  %d", aux->pkey_len, ntohs(aux->pkey_len));

			aux->pubKey = (unsigned char *)malloc(aux->pkey_len);
			char *pk = (unsigned char*)buffer+pos;

			//printf("\n\n%d\nChiave ricevuta:\n", ntohs(aux->pkey_len));
			for (uint16_t i = 0; i < ntohs(aux->pkey_len); i++){
				aux->pubKey[i] = pk[i];
				//printf("%c",pk[i]);
				incPos(&pos, sizeof(unsigned char));
			}
			//printf("\n");
			break;
		case PING_OPCODE:
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;
		case KEY_OPCODE:
			//printf("Sono quiii!\n");
			memcpy(&aux->pkey_len, buffer+pos, checkPos(&pos, sizeof(aux->pkey_len)));
			incPos(&pos, sizeof(aux->pkey_len));
			aux->peerkey = malloc(ntohs(aux->pkey_len)+1); //POSSIBILE ERRORE
			for (uint64_t i = 0; i < ntohs(aux->pkey_len); i++){
				aux->peerkey[i] = (unsigned char)*(buffer+pos);
				//printf("%d,%c,%c", i, *(buffer+pos),aux->peerkey[i]);
				incPos(&pos, sizeof(char));
			}
			memcpy(&aux->sign_len, buffer+pos, checkPos(&pos, sizeof(aux->sign_len)));
			incPos(&pos, sizeof(aux->sign_len));
			aux->sign = malloc(ntohs(aux->sign_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->sign_len); i++){
				aux->sign[i] = (unsigned char)*(buffer+pos);
				incPos(&pos, sizeof(char));
				//printf("%u", aux->sign[i]);
			}
			break;
		case AUTH2_OPCODE:
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			break;
		case AUTH3_OPCODE:
			memcpy(&aux->nonce, buffer+pos, checkPos(&pos, sizeof(aux->nonce)));
			incPos(&pos, sizeof(aux->nonce));
			memcpy(&aux->sign_len, buffer+pos, checkPos(&pos, sizeof(aux->sign_len)));
			incPos(&pos, sizeof(aux->sign_len));
			aux->sign = malloc(ntohs(aux->sign_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->sign_len); i++){
				aux->sign[i] = (unsigned char)*(buffer+pos);
				incPos(&pos, sizeof(char));
				//printf("%u", aux->sign[i]);
			}
			break;
		case AUTH4_OPCODE:
			memcpy(&aux->sign_len, buffer+pos, checkPos(&pos, sizeof(aux->sign_len)));
			incPos(&pos, sizeof(aux->sign_len));
			aux->sign = malloc(ntohs(aux->sign_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->sign_len); i++){
				aux->sign[i] = (unsigned char)*(buffer+pos);
				incPos(&pos, sizeof(char));
				//printf("%u", aux->sign[i]);
			}
			memcpy(&aux->cert_len, buffer+pos, checkPos(&pos, sizeof(aux->cert_len)));
			incPos(&pos, sizeof(aux->cert_len));
			//printf("\n POS1 %d e DIM CERT LEN %d\n", pos, ntohs(aux->cert_len));
			aux->cert = malloc(ntohs(aux->cert_len)+1);
			for (uint64_t i = 0; i < ntohs(aux->cert_len); i++){
				aux->cert[i] = (unsigned char)*(buffer+pos);
				incPos(&pos, sizeof(char));
				//printf("%u", aux->cert[i]);
				//printf("%d",pos);
			}
			//printf("sign %d e cert %d\n", aux->sign_len, aux->cert_len);
			break;
		default:
			break;
	}
	toHost(aux);
	return notBufferOverflow;
}

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr, int dec, uint64_t nonce){
  	int ret=-1;
	uint32_t senderId;
  	void *buffer = malloc(1 + sizeof(senderId) + MAX_BUFFER_SIZE + TAG_SIZE + IV_SIZE);
  	int buffersize = 1 + MAX_BUFFER_SIZE + TAG_SIZE + IV_SIZE;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	sdAux = socket;

	signal(SIGALRM, ALARMhandler);
	do{
		if(!isAlarmFree){
			//printf("Start alarm\n");
			timeout = 0;
			alarm(waitTime);
		}
		//printf("Waiting new message\n");
		ret = recvfrom(socket, buffer, buffersize, 0, (struct sockaddr*)mitt_addr, &addrlen);
		//printf("New message!!!\n");

		//printf("exit:%d    Time:%d \n", exitOnError, timeout);
		if(exitOnError == FALSE && timeout == 1){
			timeout = 0;
			perror("TIMEOUT recivefrom\n");
			return -1;
		}

		//BIO_dump_fp(stdout, (const char *)buffer, 64);
		
		u_int8_t isEncr;
		memcpy(&isEncr, buffer, 1);

		if(isEncr != FALSE){

			//unsigned char iv_gcm[] = "123456789012" ;
			unsigned char iv_gcm[IV_SIZE];
			unsigned char *ct, *tag, pt[MAX_BUFFER_SIZE], aad[5 + IV_SIZE];
			int pos = 1;
			

			memcpy(&senderId, buffer+pos, sizeof(senderId));
			pos += sizeof(senderId);
			//printf("Id ricevuto :%d\n", senderId);

			memcpy(iv_gcm, buffer+pos, IV_SIZE);
			pos += IV_SIZE;

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
			unsigned char k[SIM_KEY_LEN];
			if(senderId == (MAX_USERS+1)){
				strcpy(k, key_gem_recive);
				//printf("client key: %s \n",k);
			}else{
				strcpy(k, key_client);
			}

			if(isServerRecive == TRUE){
				//get_buf_column_by_id("loggedUser.csv", (int)senderId, 5, k);
				readKey((int)senderId, k);
			}
	
			//printf("%s\n", k);
			sprintf(symKey, "%s", k);


			memcpy(aad, buffer, 5 + IV_SIZE);
			symDecrypt(pt, MAX_BUFFER_SIZE, k, iv_gcm, ct, tag, aad, 5 + IV_SIZE);

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

		ret = deserialize_message(buffer, message, isEncr);

		/*if(message->opcode == PING_OPCODE){
			pingHandler(*message, mitt_addr);
		}*/
	}while(ret==-1 || (isClinetSecondProcess && message->opcode == PING_OPCODE));
	alarm(0);
	return ret;
}
