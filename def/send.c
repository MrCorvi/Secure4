
#include "../header/send.h"
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/crypto.h>
#include<openssl/pem.h>


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
	aux.peerkey = msg->peerkey;
	aux.pkey_len = htons(msg->pkey_len); //da rivedere
	aux.cert = msg->cert;
	aux.cert_len = htons(msg->cert_len);
	aux.sign =msg->sign;
	aux.sign_len = htons(msg->sign_len);

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
			//printf("login, buffer contienete: %d, %d e poi %d\n", aux.opcode, aux.my_id, aux.my_listen_port);
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
			//printf("AUX FLAG INVIATO: %u <--> %d\n ", aux.flag, aux.flag );
			break;
		case KEY_OPCODE:
			memcpy(buffer+pos, &aux.pkey_len, sizeof(aux.pkey_len));
			pos+=sizeof(aux.pkey_len);
			//printf("KEY OPCODE e chiave lunga %d \n", aux.pkey_len);
			for(int i = 0; i < msg->pkey_len; i++){
				unsigned char temp1 = aux.peerkey[i];
				memcpy(buffer+pos, &temp1, sizeof(temp1));
				char bufchar;
				memcpy(&bufchar, buffer+pos, sizeof(temp1));
				//printf("%i, %c, %c\n",i, temp1, bufchar);
				pos+= sizeof(temp1);
			}
			break;
		case AUTH2_OPCODE:
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			break;
		case AUTH3_OPCODE:
			memcpy(buffer+pos, &aux.nonce, sizeof(aux.nonce));
			pos+=sizeof(aux.nonce);
			memcpy(buffer+pos, &aux.sign_len, sizeof(aux.sign_len));
			pos+=sizeof(aux.sign_len);
			for(int i = 0; i < msg->sign_len; i++){
				memcpy(buffer+pos, &aux.sign[i], sizeof(aux.sign[i]));
				pos+= 1; //sizeof(temp1);
				//printf("%u",aux.sign[i]);
			}
			break;
		case AUTH4_OPCODE:
			memcpy(buffer+pos, &aux.sign_len, sizeof(aux.sign_len));
			pos+=sizeof(aux.sign_len);
			for(int i = 0; i < msg->sign_len; i++){
				//unsigned char temp1 = aux.sign[i];
				memcpy(buffer+pos, &aux.sign[i], sizeof(aux.sign[i]));
				pos+= 1; //sizeof(temp1);
				//printf("%u",aux.sign[i]);
			}
			memcpy(buffer+pos, &aux.cert_len, sizeof(aux.cert_len));
			pos+=sizeof(aux.cert_len);
			for(int i = 0; i < msg->cert_len; i++){
				//unsigned char temp1 = aux.cert[i];
				//memcpy(buffer+pos, &temp1, sizeof(temp1));
				memcpy(buffer+pos, &aux.cert[i], sizeof(aux.cert[i]));
				pos+= 1; //sizeof(temp1);
				//printf("%u",aux.cert[i]);
				//printf("%u",temp1);
			}
			//printf("sign %d e cert %d\n", aux.sign_len, aux.cert_len);
			break;
		default:
			break;
	}

	return pos;
}


void send_message(struct message *m, struct sockaddr_in * dest_addr,int socket, uint8_t encrypt){

	void *buf;
	buf = malloc(1 + MAX_BUFFER_SIZE + TAG_SIZE + 12);	
	int ret;


	// packet creation
	//printf("ptLen: %d\n", m->ptLen); 
	int len = 1 + MAX_BUFFER_SIZE + TAG_SIZE + 12;
	serialize_message(buf, m);

	if(encrypt == TRUE){
		//create key
		unsigned char key_gem[]= "1234567890123456";
		//unsigned char iv_gcm[] = "123456789012" ;
		unsigned char iv_gcm[12];
		
		//Cypher
		unsigned char *ct   = (unsigned char*)malloc(MAX_BUFFER_SIZE);	
		unsigned char *tag  = (unsigned char*)malloc(TAG_SIZE);
		unsigned char pt[MAX_BUFFER_SIZE];
		int ptLen = MAX_BUFFER_SIZE;
		int pos = 0;

		RAND_poll();

		//sprintf(iv_gcm, "%-12d", m->nonce - 1);
		RAND_bytes(iv_gcm, 12);
		//printf("									iv: |%s|", iv_gcm);

		memcpy(pt, buf, MAX_BUFFER_SIZE);

		symEncrypt(pt, MAX_BUFFER_SIZE, key_gem, iv_gcm, ct, tag);


		memcpy(buf, &encrypt, 1);
		pos+= 1;

		memcpy(buf+pos, (const char *) iv_gcm, 12);
		pos+= 12;

		memcpy(buf+pos, (const char *) ct, MAX_BUFFER_SIZE);
		pos+= MAX_BUFFER_SIZE;

		memcpy(buf+pos, (const char *) tag, TAG_SIZE);
		pos+= TAG_SIZE;

		//printf("Buffer : \n");
   		// BIO_dump_fp(stdout, (const char *)buf, 1 + MAX_BUFFER_SIZE + TAG_SIZE + 12);


		free(ct);
		free(tag);
	}

	ret = sendto(socket, buf, len , 0, (struct sockaddr*)dest_addr, sizeof(struct sockaddr_in));	
	if(ret<0){
		perror("sendto ERROR");
		exit(1);		
	}	

}