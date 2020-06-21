#include<arpa/inet.h>
#include<errno.h>
#include<netinet/in.h>
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/crypto.h>
#include<openssl/pem.h>
#include<stdio.h>
#include<signal.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<time.h>
#include<math.h>
#include<string.h>
#include<unistd.h>
#ifndef MESSAGE_H
	#define MESSAGE_H
	#include "header/message.h"
#endif
#ifndef COMUNICATION_H
    #define COMUNICATION_H
    #include "header/send.h"
    #include "header/receive.h"
#endif
#include "header/receive.h"
#include "header/utilityFile.h"
#include "header/keyStore.h"

#define BUFLEN 1024

char* pwd;
char* filename = "loggedUser.csv";
struct sockaddr_in my_addr, listen_addr;
int num_bind =0;
int sv_port;
int sd_listen; //each process use one to answer a request
unsigned char symKey[SIM_KEY_LEN];
uint32_t cs;

int socket_creation(){
	struct sockaddr_in my_addr;
	int sd = socket(AF_INET, SOCK_DGRAM, 0); // just socket creation (not yet IP or port)

	//addres creation
	memset(&my_addr,0, sizeof(my_addr)); //pulizia
	my_addr.sin_family= AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(sv_port+num_bind);

	int ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret!=0){
  		printf("Errore Binding: %s\n", strerror(errno));		
		exit(1);
	}
	printf("\033[1;32m");
	printf("BIND SERVER ");
	printf("\033[0m"); 
	printf("CHILD %d to the port %d: %d\n", num_bind, ntohs(my_addr.sin_port), ret);
	return sd;
}

int handleErrors(){
    printf("An error occourred \n");
    exit(1);
}

unsigned char *get_secret_ec(size_t *secret_len, struct sockaddr_in *cl_addr,int sd){
	EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	EVP_PKEY *pkey = NULL, *peerkey, *dh_params = NULL;
	
    char *str = "./pubkeys/ec_pubkeyserver.pem";
    printf("%s\n", str);

	// Create the context for parameter generation 
	if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();

	// Initialise the parameter generation 
	if(!EVP_PKEY_paramgen_init(pctx)) handleErrors();

	// We're going to use the ANSI X9.62 Prime 256v1 curve 
	if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) handleErrors();

	// Create the parameter object dh_params 
	if (!EVP_PKEY_paramgen(pctx, &dh_params)) handleErrors();

	// Create the context for the key generation 
	if(NULL == (kctx = EVP_PKEY_CTX_new(dh_params, NULL))) handleErrors();

	// Generate the key 
	if(!EVP_PKEY_keygen_init(kctx)) handleErrors();
	if (!EVP_PKEY_keygen(kctx, &pkey)) handleErrors();

    // ricevi
   	struct message aux;
	printf("Attendo chiave\n");
    recv_message(sd, &aux, (struct sockaddr*)cl_addr, FALSE, 0);
	printf("Chiave ricevuta\n");
	printf("Di lunghezza %d\n", aux.pkey_len );
	// peerkey è consistente, controllato
	for (int ii = 0; ii < aux.pkey_len; ii++){
            printf("%c", aux.peerkey[ii]);
    }
	
    BIO *bio = NULL;
    if ((bio = BIO_new(BIO_s_mem())) == NULL)
      return NULL;

    BIO_write(bio, aux.peerkey, aux.pkey_len);
    //printf("bio+128: \n"); // è uguale a bio1 , già controllato
    //BIO_dump_fp(stdout, bio, aux.pkey_len+128);
	PEM_read_bio_PUBKEY(bio, &peerkey, NULL, NULL);
    BIO_free(bio);

    //printf("YEEE: \n"); // è uguale a bio1 , già controllato
    //BIO_dump_fp(stdout, peerkey, aux.pkey_len);

	// invia
	FILE* p1w = fopen(str, "w");
    if(!p1w){ printf("Error: cannot open file %s\n", str); exit(1); }
    PEM_write_PUBKEY(p1w, pkey);
    fseek(p1w, 0L, SEEK_END);
    int size = ftell(p1w);
    fseek(p1w, 0L, SEEK_SET);
    fclose(p1w);

	BIO *bio2 = NULL;
    if ((bio2 = BIO_new(BIO_s_mem())) == NULL)
      return NULL;
    //PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
    if (0 == PEM_write_bio_PUBKEY(bio2, pkey)){
      BIO_free(bio2);
      return NULL;
    }

    char *pem = (char *) calloc(1, size + 1);
    BIO_read(bio2, pem, size);
    BIO_free(bio2);
    printf("sizeof %d\n", size);
    for (int i = 0; i < size; i++){
        printf("%c",  pem[i]);
    }

	struct message aux_ack;
    aux_ack.opcode = KEY_OPCODE;    
    aux_ack.peerkey = pem;
    aux_ack.pkey_len = size;
	send_message(&aux_ack, cl_addr, sd, FALSE);

	// Create the context for the shared secret derivation 
	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))   printf("ERRORE 1\n");// handleErrors();
	
	// Initialise 
	if(EVP_PKEY_derive_init(ctx)<=0)  printf("ERRORE 2\n");//handleErrors();
	
	// Provide the peer public key 
	if(EVP_PKEY_derive_set_peer(ctx, peerkey)<=0)  printf("ERRORE 3\n");//handleErrors();
	
	// Determine buffer length for shared secret 
	if(EVP_PKEY_derive(ctx, NULL, secret_len)<=0)  printf("ERRORE 4\n");//handleErrors();
	
	// Create the buffer 
	secret = (unsigned char*)(malloc((int)*secret_len));
	if(!secret) handleErrors();
	
	// Derive the shared secret 
	if(EVP_PKEY_derive(ctx, secret, secret_len)<=0)  printf("ERRORE 6\n");//handleErrors();
	
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(dh_params);
	EVP_PKEY_CTX_free(pctx);
    
	printf("SEGRETO: \t");
	BIO_dump_fp(stdout, (const char*)secret, *secret_len);
	
	return secret;
}

unsigned char* hash(unsigned char* secret){
	
	unsigned char* dig;
	int digestlen;
	EVP_MD_CTX* Hctx;

	dig = (unsigned char*)malloc(32);
	Hctx = EVP_MD_CTX_new();

	EVP_DigestInit(Hctx, EVP_sha256());
	EVP_DigestUpdate(Hctx, secret, sizeof(secret));
	EVP_DigestFinal(Hctx, dig, (unsigned int*)&digestlen);

	//printf("Digest:\n");
	//BIO_dump_fp(stdout, (const char*)dig, digestlen);

	return dig;
}

struct message pack_ack(uint32_t id, uint32_t nonce){

    struct message aux;
    aux.opcode = ACK_OPCODE;
    aux.my_id = id;
	aux.nonce = nonce;
    return aux;
}

struct message pack_challenge(){

	RAND_poll();
	RAND_bytes((unsigned char *)&cs, sizeof(uint32_t));
	//printf("CS: %d\n", cs);
	//cs = 66; // costante

	struct message aux;
	aux.opcode = AUTH2_OPCODE;
	aux.nonce = cs; 
	return aux;
}

struct message pack_err(uint32_t id, u_int32_t nonce){

    struct message aux;
    aux.opcode = REPLY_OPCODE;
    aux.my_id = id;
	aux.nonce = nonce;
    aux.flag = 2;
    return aux;
}

struct message pack_list_ack(uint32_t nonce){
    struct message aux;
	uint16_t len;
    aux.opcode = ACK_LIST;
	get_ID_column("loggedUser.csv", &len, aux.onlinePlayers);
	aux.nOnlinePlayers = len;
	aux.nonce = nonce;
	return aux;
}

struct message pack_reply_message(uint16_t flag, uint32_t cl_id, uint16_t dest_id_aux, uint32_t nonce){
	struct message aux;
    aux.opcode = REPLY_OPCODE;
    aux.my_id = cl_id;
    aux.dest_id = dest_id_aux;
    aux.flag = flag;
    aux.nonce = nonce;
    aux.pkey_len = 0;

	return aux;
}

struct message packCertificateAndSign(unsigned char* signed_challange,int sign_len, char* certserver_file_name){

	FILE* cert_file = fopen(certserver_file_name, "r");
    if(!cert_file) handleErrors();
    X509* cert = PEM_read_X509(cert_file, NULL, (pem_password_cb *)pwd, NULL); 

	unsigned char* cert_buf = NULL;
	int cert_size = i2d_X509(cert, &cert_buf);
	if(cert_size<0){printf("cert_size <0\n"); exit(1);}

	//printf("SIGN SIZE %d e sizeof(int):%lu\n", sign_len, sizeof(int));

	unsigned char *tmpPtr;		// because d2i_X509 moves the ptr 
	tmpPtr = malloc(cert_size);
	for(int i=0; i<cert_size; i++)
		tmpPtr[i] = cert_buf[i];

	/*printf("Signed challenge\n");
	for(int i=0; i<sign_len; i++)
		printf("%u", signed_challange[i]);
	printf("\n");*/

	struct message aux;
	aux.opcode = AUTH4_OPCODE;
	aux.sign = signed_challange;
	aux.sign_len = sign_len;
	aux.cert = tmpPtr;
	aux.cert_len = cert_size;

	OPENSSL_free(cert_buf);

	return aux;
}

struct sockaddr_in setupAddress(char *ip, int port){
    struct sockaddr_in other_addr;
    memset(&other_addr,0, sizeof(other_addr)); //pulizia
    other_addr.sin_family= AF_INET;
    other_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip , &other_addr.sin_addr);
    return other_addr;
}


unsigned char* sign(char* message, int* signature_len, int msg_len){

	unsigned char* signature;   
	char* serverpkey_file_name= "./CA/serverprvkey.pem";
	FILE* fp = fopen(serverpkey_file_name, "r");
	if(!fp) handleErrors();
	EVP_PKEY* prvkey = PEM_read_PrivateKey(fp,NULL,
	NULL ,pwd); 
	//EVP_PKEY* prvkey = PEM_read_PrivateKey(fp,NULL, NULL,NULL);
	if(!prvkey){printf("Errore prvkey\n"); handleErrors();}
	fclose(fp);
	
	signature = malloc(EVP_PKEY_size(prvkey));
	EVP_MD_CTX* sctx = EVP_MD_CTX_new();
	EVP_SignInit(sctx, EVP_sha256());
	EVP_SignUpdate(sctx, (unsigned char*)message, msg_len); // costante magica sizeof(message));
	EVP_SignFinal(sctx, signature, (unsigned int*)signature_len, prvkey);
	
	return signature;
}



int checkNonce(uint32_t id, uint32_t nonce_recived, int inc){
	uint32_t nonce_stored = atoi(get_column_by_id(filename, id , 4));

	//check if the nonce received is 1 more of the one stored
	if((nonce_stored+1) != nonce_recived){
		printf("Errore: il nonce ricevuto non era quello aspettato\n");//Da stabilire con edo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		printf("Nonce recived: %d		Nonce stored: %d\n", nonce_recived, nonce_stored);
		return 0;
	}

	//update the nonce stored
	const char *ip   = get_column_by_id(filename, id, 2);
	uint16_t port = (short)atoi(get_column_by_id(filename, id, 3));
	update_row(filename, id, ip, port, nonce_stored + inc);
	return 1;
}





int timeout = 0, waitingId;
void  ALARMhandler(int sig){
	signal(SIGALRM, SIG_IGN);          /* ignore this signal       */
	printf("TIME OUT: 1 minute of no responce from the user\nThe user is now delited\n");
	timeout = 1;
	int ret = remove_row_by_id(filename, waitingId);
	printf("The user %d is now delited from the online players\n", waitingId);
	//if not pack err
	if(ret==-1){
		printf("ID non presente!\n");
		return;
	}
	shutdown(sd_listen, SHUT_RDWR);
	clearKey(waitingId);
	signal(SIGALRM, ALARMhandler);     /* reinstall the handler    */
}





void childePingCode(){

	while(TRUE){
		sleep(5);

		uint16_t dim, IDs[MAX_USERS];
		get_ID_column(filename, &dim, IDs);

		for(uint16_t i=0; i<dim; i++)
			printf("ID %u : %u", i, IDs[i]);
		
		for(uint16_t i=0; i<dim; i++){
			char ip[30], port_buf[30], key[SIM_KEY_LEN];
			get_buf_column_by_id(filename, IDs[i], 2, ip);
			get_buf_column_by_id(filename, IDs[i], 3, port_buf);
			readKey(IDs[i], key);
			uint16_t port = (short)atoi(port_buf);
			printf("id %u has		ip: %s		port:%u			key:%s\n", IDs[i], ip, port, key);

		}
	}

}



int handle_request(struct message* aux, struct sockaddr_in *cl_addr,int sd){

    uint16_t opcode = (uint16_t) aux->opcode;   
	char *dest_ip;
	uint16_t dest_port;   
	char str[INET_ADDRSTRLEN];
	sd_listen = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
	//int nonce_len_cs = (unsigned int)floor(log10(cs))+1;
	char *ch_ca, *ch_cs;

	setIsServerReciver();
	setIsServerSend();

	signal(SIGALRM, ALARMhandler);

	printf("opcode: %d\n", opcode);

    switch(opcode){

        case LOGIN_OPCODE:

            printf("Login request\n");
			
			int ret = get_row_by_id(filename, aux->my_id);
			printf("row : %d\n", ret);
			if(ret!=-1){
				printf("ERRORE GIA' LOGGATO, da gestire con Err pack");
				// per ora inserisce comunque per agevolare testing
				struct message m = pack_err(aux->my_id, aux->nonce+1);
            	send_message(&m, cl_addr, sd, FALSE);
				close(sd_listen);
				break;
			}

			printf("PACK CHALLENGE\n");
			struct message m_challenge = pack_challenge();
			send_message(&m_challenge, cl_addr, sd, FALSE);
			
			struct message m_response;
			struct sockaddr* cl_addr2;
			recv_message(sd, &m_response, cl_addr2, FALSE, 0); //c'era (struct sockaddr*)&cl_addr //
			//printf("\nCu: %u", m_response.nonce);
			//printf("Sign len. %d\n", m_response.sign_len);
			/*for(uint32_t i=0; i<m_response.sign_len; i++){
				printf("%u", m_response.sign[i]);
			}*/
			
			// verifica
			char client_file_name[32];
			char id[2];
			sprintf(id, "%d", aux->my_id);
			strcpy(client_file_name, "./keys/rsa_pubkey");
			strcat(client_file_name, id);
			strcat(client_file_name,".pem");
			printf("%s\n", client_file_name);

			EVP_PKEY* user_pubkey;
			//char* client_file_name= "./keys/rsa_pubkey1.pem";
			FILE* fp = fopen(client_file_name, "r");
			if(!fp) { printf("can't open file\n"); handleErrors();}
			user_pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
			if(!user_pubkey) handleErrors();
			fclose(fp);
			
			int nonce_len_cs = (unsigned int)floor(log10(cs))+1;
    		ch_cs = malloc(nonce_len_cs);
    		sprintf(ch_cs, "%u", cs);
			//char *test= "66"; //costante magica
			const EVP_MD* md = EVP_sha256();
			EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
			if(!md_ctx) handleErrors();
			ret = EVP_VerifyInit(md_ctx, md);
			if(ret==0){ printf("Error verify init\n"); handleErrors();}
			ret = EVP_VerifyUpdate(md_ctx, ch_cs, nonce_len_cs);
			if(ret==0){ printf("Error verify update\n"); handleErrors();}
			ret = EVP_VerifyFinal(md_ctx, m_response.sign, m_response.sign_len, user_pubkey);
			if(ret!=1){ printf("Error verify final\n"); handleErrors();}
			printf("Cs verified");
			EVP_PKEY_free(user_pubkey);
			EVP_MD_CTX_free(md_ctx);
		
			// firma ca e certificato
			printf("Nonce\n");
			int nonce_len_ca = (unsigned int)floor(log10(m_response.nonce))+1;
			ch_ca = malloc(nonce_len_ca);
    		sprintf(ch_ca, "%u", m_response.nonce );
			//for(int i=0; i<nonce_len_ca;i++)
			//	printf("%c", ch_ca[i]);
			int sign_len;
			unsigned char* signed_challange = sign(ch_ca, &sign_len, nonce_len_ca);
			//for(int i=0; i<sign_len; i++)
			//	printf("%u", signed_challange[i]);
			//printf("Firma %s\n\n CON LUNGHEZZA %d", signed_challange, sign_len);

			char* certserver_file_name = "./CA/ServerCybersec_cert.pem";
			struct message aux_cert = packCertificateAndSign(signed_challange, sign_len, certserver_file_name);
			send_message(&aux_cert, cl_addr, sd, FALSE);
		
			size_t secret_len = SECRET_SIZE;
			//costante magica
    		unsigned char* secret = get_secret_ec(&secret_len, cl_addr, sd);  //"0123456789";//
			// Hashing to increase entropy
			unsigned char* digest= hash(secret);


			char buffer[MAX_BUFFER_SIZE];
			inet_ntop(AF_INET, &(cl_addr->sin_addr), str, INET_ADDRSTRLEN);
			int cl_port = aux->my_listen_port;
			sprintf(buffer,"%d,%s,%d,%d,", aux->my_id, str, cl_port, cs); //costante magica
			char key[SIM_KEY_LEN] = "";
			for(int i=0; i<32; i++){
				char tempC[5];
				sprintf(tempC,"%02x", digest[i]);
				strcat(buffer, tempC);
				strcat(key, tempC);
			}
			append_row(filename, buffer);
			writeKey(aux->my_id, key);
            
			char temp_key[SIM_KEY_LEN];
			readKey(aux->my_id, temp_key);
			//printf("After 1s, parent read: %s\n", temp_key);

			break;
		case LIST_OPCODE:
            printf("List request from ID: %d\n", aux->my_id);

			//check nonce
			if(!checkNonce(aux->my_id, aux->nonce, 2))
				break;

            struct message ackList = pack_list_ack(aux->nonce + 1);
			printf("nonce: %d\n", ackList.nonce);
            send_message(&ackList, cl_addr, sd, TRUE);
            break;
		case MATCH_OPCODE:

			dest_ip = (char*)get_column_by_id(filename, aux->dest_id, 2);
			uint32_t nonce_stored = atoi(get_column_by_id(filename, aux->my_id , 4));
			uint32_t nonce_sender = aux->nonce;

			//check if the id required is online
			if(dest_ip==NULL){
				printf("The id %u is not online\n", aux->dest_id);
				//update nonce
				char source_ip_err[50];
				get_buf_column_by_id(filename, aux->my_id, 2, source_ip_err);
				uint16_t source_port_err = (uint16_t)atoi(get_column_by_id(filename, aux->my_id, 3));
				update_row(filename, aux->my_id, source_ip_err, source_port_err, nonce_stored + 2);

				struct message m = pack_err(aux->my_id, nonce_stored + 2);
				//printf("				---		---		nonce:  %d\n", m.nonce);
				//set symmetric key to talk with reciver
				//get_buf_column_by_id("loggedUser.csv", (int)aux->my_id, 5, (char*)symKey);
				readKey((int)aux->my_id, (char*)symKey);
            	send_message(&m, cl_addr, sd, TRUE);
				close(sd_listen);
				break;
			} 

			dest_port = (short)atoi(get_column_by_id(filename, aux->dest_id, 3));

			//check nonce
			if(!checkNonce(aux->my_id, nonce_sender, 1))
				break;


			printf("%d <--> %d \n", aux->dest_id, aux->dest_id);
			printf("DEST IP: %s\n", dest_ip);
			printf("DEST PORT; %u\n", dest_port);

			printf("Nonce recived: %d		Nonce stored: %d\n", nonce_sender, nonce_stored);
			//check if the nonce received is 1 more of the one stored
			if((nonce_stored+1) != nonce_sender){
				printf("Errore: il nonce ricevuto non era quello aspettato\n");//Da stabilire con edo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
				break;
			}

			//update the nonce stored
			char    *source_ip   = (char*)get_column_by_id(filename, aux->my_id, 2);
			uint16_t source_port = (short)atoi(get_column_by_id(filename, aux->my_id, 3));
			update_row(filename, aux->my_id, source_ip, source_port, nonce_stored + 1);

			//set the reciver nonce
			uint32_t nonce_reciver = atoi(get_column_by_id(filename, aux->dest_id, 4));
			aux->nonce = nonce_reciver + 1;
            
			sd_listen = socket(AF_INET, SOCK_DGRAM, 0);

			//addres creation
			memset(&listen_addr,0, sizeof(listen_addr)); //pulizia
			listen_addr.sin_family= AF_INET;
			listen_addr.sin_port = htons(dest_port);
			inet_pton(AF_INET, dest_ip , &listen_addr.sin_addr);


			//set symmetric key to talk with reciver
			//get_buf_column_by_id("loggedUser.csv", (int)aux->dest_id, 5, (char*)symKey);
			readKey((int)aux->dest_id, (char*)symKey);
            send_message(aux, &listen_addr, sd_listen, TRUE);

			
			printf("waiting reply\n");
			dest_ip = (char*)get_column_by_id(filename, aux->dest_id, 2);
			dest_port = (short)atoi(get_column_by_id(filename, aux->dest_id, 3));

			struct message aux_risp;
			alarm(TIMEOUT_TIME);
			waitingId = aux->dest_id;
			int req = recv_message(sd_listen, &aux_risp, (struct sockaddr*)&listen_addr, FALSE, 0); //3000 receive port and then pass message to others
			
			if(req!=1){
				printf("Errore (andra' implementato ERR_OPCODE)\n");
				close(sd_listen);
				exit(1);
			}

			if(timeout == 1){
				timeout = 0;

				//struct message resp = pack_reply_message(0, aux->dest_id, aux->my_id, nonce_stored + 2);
				printf("[0;31mClosing the comunication[0m\n");
				aux_risp.flag = 0;
				//break;
			}else{
				//Check corret nonce
				printf("Nonce 			recived: %d		Nonce stored: %d\n", aux_risp.nonce, nonce_reciver);
				if( aux_risp.nonce != (nonce_reciver + 2)){
					printf("Errore: il nonce ricevuto dal reciver non era quello aspettato\n");//Da stabilire con edo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
					break;
				}



				//send responce and public key of sender to the reciver
				printf("sending to %d public key of %d\n", aux->dest_id, aux->my_id);
				//uint16_t pkSize = getPublicKeySize(aux->my_id);
				//unsigned char pk_dest = (unsigned char *) malloc(pkSize + 1);
				unsigned char pk_dest[5000];
				uint16_t pkSize = getPublicKey(pk_dest, aux->my_id);

				printf("Public key:      %s\n", pk_dest);
				source_ip   = (char*)get_column_by_id(filename, aux->my_id, 2);
				source_port = (short)atoi(get_column_by_id(filename, aux->my_id, 3));

				struct message risp;
				risp.opcode = REPLY_OPCODE;
				risp.dest_ip = (uint32_t)*source_ip;
				risp.dest_port = source_port;
				risp.flag = aux_risp.flag;
				risp.nonce = nonce_reciver + 3;
				risp.pkey_len = pkSize;
				risp.pubKey = pk_dest;

				//reciver publick key
				
				printf("Public key:      \n%s\n", pk_dest);
				
				//set symmetric key to talk with reciver
				//get_buf_column_by_id("loggedUser.csv", (int)aux->dest_id, 5, (char*)symKey);
				readKey((int)aux->dest_id, (char*)symKey);
				send_message(&risp, &listen_addr, sd_listen, TRUE);

				//free(pk_dest);

				dest_ip = (char*)get_column_by_id(filename, aux->dest_id, 2);
				update_row(filename, aux->dest_id, dest_ip, dest_port, nonce_reciver + 3);
				printf("												DEST IP: %s\n", dest_ip);
			}


			//send responce to the sender
			printf("sending to %d public key of %d\n", aux->my_id, aux->dest_id);
			unsigned char pk[5000];
			uint16_t pkSizeSender = getPublicKey(pk, aux->dest_id);

    		//printf("Public key:      %s\n", pk);

			struct message rispSender;
			rispSender.opcode = REPLY_OPCODE;
			rispSender.dest_ip = (uint32_t)*dest_ip;
			rispSender.dest_port = dest_port;
			rispSender.flag = aux_risp.flag;
			rispSender.nonce = nonce_stored + 2;
			rispSender.pkey_len = pkSizeSender;
			rispSender.pubKey = pk;

			//reciver publick key
			
			printf("Public key:      \n%s\n", pk);
			
			//set symmetric key to talk with reciver
			//get_buf_column_by_id("loggedUser.csv", (int)aux->my_id, 5, (char*)symKey);
			readKey((int)aux->my_id, (char*)symKey);
			send_message(&rispSender, cl_addr, sd, TRUE);

			//free(pk);



			source_ip   = (char*)get_column_by_id(filename, aux->my_id, 2);
			source_port = (short)atoi(get_column_by_id(filename, aux->my_id, 3));
			update_row(filename, aux->my_id, source_ip, source_port, nonce_stored + 2);

			break;
			
		case LOGOUT_OPCODE:
			//check nonce
			if(!checkNonce(aux->my_id, aux->nonce, 2))
				break;

			//look at .csv if correct id
			ret = get_row_by_id(filename,aux->my_id);
			//if not pack err
			if(ret==-1){
				printf("ID non presente!\n");
				return -1;
			}
			printf("rimuovo riga %d \n", ret);
			remove_row(filename, ret);
			printf("Riga rimossa!\n");
			struct message ackLogout = pack_ack(aux->my_id, aux->nonce + 1);
            send_message(&ackLogout, cl_addr, sd, TRUE);
			clearKey(aux->my_id);
			break;
		default:
			break;
    }

	return 1;
}







int main(int argc, char* argv[]){

	int ret,sd;
	struct sockaddr_in cl_addr;
	struct message m;	

	setIsServerReciver();
	setIsServerSend();
	setKeyFilename(filename);

	// argument check
	if(argc < 3){
		printf("Not enough arguments. Try Again\n");
		printf("./server listen_server_port file_pwd\n");
		exit(0);
	}
	sv_port = atoi(argv[1]); 
	pwd = argv[2];

	// address creation
	memset(&my_addr,0, sizeof(my_addr)); // cleaning
	my_addr.sin_family= AF_INET;
	my_addr.sin_addr.s_addr = INADDR_ANY;
	my_addr.sin_port = htons(sv_port); // host to net

	// main socket creation
	sd = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
	ret = bind(sd, (struct sockaddr*)&my_addr, sizeof(my_addr));
	if(ret!=0){
			perror("Binding Error\n");			
			exit(1);			
	}
	printf("\033[1;32m");
	printf("BIND SERVER ");
	printf("\033[0m"); 
	printf("PADRE alla porta %d: %d\n",ntohs(my_addr.sin_port), ret);

	createKeyArray();
	//to handel the ping check 
	pid_t pidPing = fork();
	num_bind++;

	if(pidPing==-1){
		printf("Fork Error while creating ping process\n");
		exit(1);		
	}	
	if(pidPing==0){ // child process
		int sd_child = socket_creation();	
	
		printf("Endling Pings\n");
		childePingCode();
		close(sd_child);
		return 0;
	}

	while(1){		

		pid_t pid;
		int req = recv_message(sd, &m, (struct sockaddr*)&cl_addr, TRUE, 0); //3000 receive port and then pass message to others
		printf("padre server RICEVO %d, %d E %d\n", m.opcode, m.my_id, m.my_listen_port);
		if(req!=1){
            printf("Errore (andra' implementato ERR_OPCODE)\n");
			close(sd);
			exit(1);
		}
		pid = fork();
		num_bind++;

		if(pid==-1){
			printf("Fork Error\n");
			exit(1);		
		}	
		if(pid==0){ // child process
			int sd_child = socket_creation();	
		
           	ret = handle_request( &m, &cl_addr, sd_child);
			printf("End Message handling\n");
            close(sd_child);
			exit(0);
		}
		
	}
    

}