#include<sys/types.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<sys/sendfile.h>
#include<openssl/evp.h>
#include<openssl/ec.h>
#include<openssl/crypto.h>
#include<openssl/pem.h>
#include<openssl/x509_vfy.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<semaphore.h> 
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<signal.h>
#include<string.h>
#include<math.h>
#include "header/forza4Engine.h"
#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"header/message.h"
#endif
#include "header/send.h"
#include "header/receive.h"

#define CMD_UNKNOWN 0
#define CMD_HELP 1
#define CMD_LIST 2
#define CMD_MATCH 3
#define CMD_LOGOUT 4
#define CMD_EMPTY 5

uint16_t dest_id;
struct sockaddr_in cl_address, cl_listen_addr, sv_addr;
char *sv_ip;
int sv_port, cl_id, cl2_id, cl_main_port, cl_secondary_port;
int sd, secondSd;
uint32_t cu;
uint32_t nonce = 100;
sem_t *mutex_active_process, *mutex_secondary_port;

void print_help(){

	printf("Commands are the following:\n");
	printf("!help --> show all available commands\n");
    printf("!list --> get IPs of all online clients\n");
    printf("!match dest_ip -> request a challenge to the client corresponding to dest_ip\n");
	printf("!logout --> logout by the server and stop the program\n");
    
}

int get_cmd(){

	char cmd_s[128];
	
    printf("\033[0;32m>  \033[0m");
    fflush(stdin);
    if(	fgets(cmd_s, 128, stdin)==NULL){
        printf("Error fgets da gestire. Per ora terminazione forzata\n");
        exit(1);
    } 
    char *p = strchr(cmd_s, '\n');
    if(p){*p='\0';}
    
    // N.B. strncmp() compare only an initial subset CMD_DIRECT_MATCH
    // I have to be sure input is not shorter


    if(strcmp(cmd_s, "") == 0){
    	return CMD_EMPTY ;
	}

	if(strlen(cmd_s)<5){
    	return CMD_UNKNOWN ;
	}

    if(strncmp(cmd_s, "!help",5)==0){
        return CMD_HELP;
    }

    if(strncmp(cmd_s, "!list",5)==0){
        return CMD_LIST;
    }

	if (strlen(cmd_s)<6){
    	return CMD_UNKNOWN;
    }

	
	if(strncmp(cmd_s, "!match",6)==0){
        // read from cmd_s and "fill" variables
        // return filled variables
        // without m is a segmentation error
		int filled = sscanf(cmd_s, "%*s %u\n", (unsigned int *)&dest_id );	
		if(filled!=1)
			return CMD_UNKNOWN;
		else
			return CMD_MATCH;
	}
	if (strlen(cmd_s)<7)
    	return CMD_UNKNOWN;

	if(strncmp(cmd_s, "!logout",7)==0)
		return CMD_LOGOUT;

    
	return CMD_UNKNOWN;
}

unsigned char* sign(unsigned char* message, int* signature_len, int msg_len){
    
    char client_file_name[32];
    char id[2];
    sprintf(id, "%d", cl_id);
    strcpy(client_file_name, "./keys/rsa_privkey");
    strcat(client_file_name, id);
    strcat(client_file_name,".pem");
    printf("%s\n", client_file_name);

	//char* client_file_name= "./keys/rsa_privkey1.pem";
	FILE* fp = fopen(client_file_name, "r");
	if(!fp) handleErrors();
	EVP_PKEY* prvkey = PEM_read_PrivateKey(fp,NULL,NULL,NULL);
	if(!prvkey){printf("Errore prvkey\n"); handleErrors();}
	fclose(fp);

    int ret;
	unsigned char* signature;
	signature = malloc(EVP_PKEY_size(prvkey));
    if(!signature){printf("Malloc error\n"); handleErrors();}
	EVP_MD_CTX* sctx = EVP_MD_CTX_new();
    if(!sctx){printf("EVP_MD_CTX error"); handleErrors();}
    ret = EVP_SignInit(sctx, EVP_sha256());
    if(ret==0){printf("EVP_SignInit error"); handleErrors();}
    ret = EVP_SignUpdate(sctx, (unsigned char*)message, msg_len); //2 costante magica sizeof(message));
    if(ret==0){printf("EVP_SignUpdate error"); handleErrors();}
	ret = EVP_SignFinal(sctx, signature, signature_len, prvkey);
    if(ret==0){printf("EVP_SignFinal error"); handleErrors();}

    /*
    printf("firmaaa di lunghezza %d:  di un messaggio lungo%d\n", *signature_len, 2);
    for(int i=0; i<*signature_len; i++){
        printf("%u", signature[i]);
    }
    printf("fine \n");
    */

	return signature;
    
}

void pack_login_message(struct message* aux){

	aux->opcode = LOGIN_OPCODE;
    aux->my_id = cl_id;
    aux->my_listen_port = cl_secondary_port;
}

void pack_list_message(struct message* aux, uint32_t id){
	aux->opcode = LIST_OPCODE;
    aux->my_id = id;
    aux->nonce = nonce;
}

void pack_logout_message(struct message* aux){

	aux->opcode = LOGOUT_OPCODE;
    aux->my_id = cl_id;
    aux->nonce = nonce;
}

void pack_match_move_message(struct message* aux, uint8_t column){
    aux->opcode = MATCH_MOVE_OPCODE;
    aux->my_id = cl_id;
    aux->addColumn = column;
    aux->ptLen = 1;
    aux->cphtBuffer = (unsigned char*)malloc(aux->ptLen);
    aux->tagBuffer  = (unsigned char*)malloc(16);
    aux->pkey_len = 0;
}

struct sockaddr_in setupAddress(char *ip, int port){
    struct sockaddr_in other_addr;
    memset(&other_addr,0, sizeof(other_addr)); //pulizia
    other_addr.sin_family= AF_INET;
    other_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip , &other_addr.sin_addr);
    return other_addr;
}

void pack_reply_message(struct message* aux, uint16_t flag, uint16_t dest_id_aux){

    aux->opcode = REPLY_OPCODE;
    aux->my_id = cl_id;
    aux->dest_id = dest_id_aux;
    aux->flag = flag;
    aux->nonce = nonce;
    aux->pkey_len = 0;
}

void pack_match_message(struct message* aux){

    aux->opcode = MATCH_OPCODE;
    aux->my_id = cl_id;
    aux->nonce = nonce;
    aux->dest_id = dest_id;
    printf("Dest id pack match: %u, %u\n", dest_id, aux->dest_id);

}

void pack_response_message(struct message* aux, int cs){

    int sign_len ;

    RAND_poll();
    RAND_bytes(&cu, sizeof(uint32_t));
    int nonce_len = (unsigned int)(floor(log10(cs)))+1;
    printf("Cu %u lungo", cu, nonce_len);
    char ch_cs[nonce_len];
    sprintf(ch_cs, "%d", cs);
    /*printf("\nSizeof ch_ch %d e Cs: ", sizeof(ch_cs));
    for(int i=0; i<2; i++)
        printf("%c", ch_cs[i]);
    printf("\n");*/
	unsigned char* signed_resp = sign(ch_cs, &sign_len, nonce_len);
	/*printf("Firma CON LUNGHEZZA %d\n", sign_len);
    for(int i=0; i<sign_len; i++)
        printf("%u", signed_resp[i]);
    printf("\n\n");*/

    aux->opcode = AUTH3_OPCODE;
    aux->nonce = cu;
    aux->sign = signed_resp;
    aux->sign_len = sign_len;

}



int setupSocket(int port){
    //addres creation
    memset(&cl_listen_addr,0, sizeof(cl_listen_addr)); //pulizia
    cl_listen_addr.sin_family= AF_INET;
    cl_listen_addr.sin_addr.s_addr = INADDR_ANY;
    cl_listen_addr.sin_port = htons(port);

    //int sd = socket(AF_INET, SOCK_DGRAM, 0); //not yet IP & port
    //int ret = bind(sd, (struct sockaddr*)&cl_listen_addr, sizeof(cl_listen_addr));
    int secondSd = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(secondSd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    int ret = bind(secondSd, (struct sockaddr*)&cl_listen_addr, sizeof(cl_listen_addr));
    if(ret!=0){
        printf("Binding Error: the port %d is already in use\n", port);			
        exit(1);			
    }

    return secondSd;
}

int nonceCheck(uint32_t nonceReceived, int incNonce, pid_t pid){
    //Nonce check
    //printf("\nNonce rec: %d       stored:%d\n", nonceReceived, nonce);
    if((nonce + 1) != nonceReceived){
        printf("Errore: recived nonce %d insted of %d\n", nonceReceived, nonce+1);//Da stabilire con edo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        return 0;
    }
    nonce+=incNonce;

    //update other branch nonce
    kill(pid, SIGUSR1);
    return 1;
}

void nonceInc(pid_t pid){
    nonce++;
    kill(pid, SIGUSR1);
}



void battleRequest(){

    sem_wait(mutex_active_process);

}



//Signal per intrrompere l'esecuzione del processo figlio
void secondaryPortRequest(){

    close(secondSd);

    //riattivo il processo padre
    sem_post(mutex_active_process);

    sem_wait(mutex_secondary_port);
    secondSd = setupSocket(cl_secondary_port);
}

void updateNonce(){
    nonce += 1;
}

unsigned char* hash(unsigned char* secret){
	
	unsigned char* digest;
	int digestlen;
	EVP_MD_CTX* Hctx;

	digest = (unsigned char*)malloc(32);
	Hctx = EVP_MD_CTX_new();

	EVP_DigestInit(Hctx, EVP_sha256());
	EVP_DigestUpdate(Hctx, secret, sizeof(secret));
	EVP_DigestFinal(Hctx, digest, &digestlen);

	printf("Digest:\n");
	BIO_dump_fp(stdout, digest, digestlen);

	return digest;
}

unsigned char *get_secret_ec(size_t *secret_len, int cl_id, struct sockaddr_in peer_addr, int flag_order){

    EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	EVP_PKEY *pkey = NULL, *peerkey =NULL, *dh_params = NULL;
    int sdAux;
    if(flag_order==2){
        printf("sd\n"); sdAux=sd;
    }
    else{
        printf("second sd\n"); sdAux=secondSd;
    }

    char str[32];
    char id[2];
    sprintf(id, "%d", cl_id);
    strcpy(str, "./pubkeys/ecc_pubkey");
    strcat(str, id);
    strcat(str,".pem");
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

    // Create the context for the shared secret derivation 
    //printf("spostatooo\n");
   
    //if(flag_order!=0){
        if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))   printf("ERRORE 1\n");
        //invia
        FILE* p1w = fopen(str, "w");
        if(!p1w){ printf("Error: cannot open file %s\n", str); exit(1); }
        PEM_write_PUBKEY(p1w, pkey);
        fseek(p1w, 0L, SEEK_END);
        int size = ftell(p1w);
        fseek(p1w, 0L, SEEK_SET);
        fclose(p1w);

        BIO *bio = NULL;
        if ((bio = BIO_new(BIO_s_mem())) == NULL) return NULL;

        if (0 == PEM_write_bio_PUBKEY(bio, pkey)){
            BIO_free(bio);
            return NULL;
        }

        char *pem = (char *) calloc(1, size + 1);
        BIO_read(bio, pem, size);
        //printf("sizeof %d\n", size);
        for (int i = 0; i < size; i++)
            printf("%c",  pem[i]);

        struct message aux;
        aux.opcode = KEY_OPCODE;    
        aux.peerkey = pem;
        aux.pkey_len = size;

        struct message ack;
        //printf("Peer addr6 %d", peer_addr);
        if(flag_order==1){
            printf("Attendo messaggio client\n");
            struct sockaddr* peer_addr2;
            recv_message(sdAux, &ack, (struct sockaddr*)&peer_addr, FALSE, 0);
        }

        printf("Inviooo a %d\n", peer_addr);
        send_message(&aux, &peer_addr, sdAux, FALSE);

        //ricevi 
        if(flag_order!=1){
            printf("Attendo messaggio client\n");
            struct sockaddr* peer_addr2;
            recv_message(sdAux, &ack, (struct sockaddr*)&peer_addr2, FALSE, 0);
        }
        printf("Chiave ricevuta\n");
        printf("Di lunghezza :::%d\n", ack.pkey_len );
        for (int ii = 0; ii < ack.pkey_len; ii++){
                printf("%c", ack.peerkey[ii]);
        }
        BIO *bio2 = NULL;
        if ((bio2 = BIO_new(BIO_s_mem())) == NULL)
            return NULL;

        BIO_write(bio2, ack.peerkey, ack.pkey_len);
        PEM_read_bio_PUBKEY(bio2, &peerkey, NULL, NULL);
        BIO_free(bio);
        BIO_free(bio2);
    /*}
    else{
        // ricevi
        struct message aux;
        printf("Attendo chiave\n");
        struct sockaddr_in peer_addr2 ;
        recv_message(sdAux, &aux, (struct sockaddr*)&peer_addr2, FALSE, 0);
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
        PEM_read_bio_PUBKEY(bio, &peerkey, NULL, NULL);
        BIO_free(bio);

        // invia
        FILE* p1w = fopen(str, "w");
        if(!p1w){ printf("Error: cannot open file %s\n", str); exit(1); }
        PEM_write_PUBKEY(p1w, pkey);
        fseek(p1w, 0L, SEEK_END);
        int size = ftell(p1w);
        fseek(p1w, 0L, SEEK_SET);
        fclose(p1w);

        BIO *bio2 = NULL;
        if ((bio2 = BIO_new(BIO_s_mem())) == NULL) return NULL;
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
        send_message(&aux_ack, &peer_addr, sdAux, FALSE);
        printf("inviatooooU_Uxf\n");
        
        // Create the context for the shared secret derivation 
        if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL)))   printf("ERRORE 1\n");// handleErrors();
    }*/
    
    // Initialise 
	if(EVP_PKEY_derive_init(ctx)<=0) handleErrors();
    
	// Provide the peer public key 
	if(EVP_PKEY_derive_set_peer(ctx, peerkey)<=0) handleErrors();

	// Determine buffer length for shared secret 
	if(EVP_PKEY_derive(ctx, NULL, &secret_len)<=0) handleErrors();

	// Create the buffer 
    secret = (unsigned char*)(malloc((int)(secret_len)));
	if(!secret) handleErrors();

	// Derive the shared secret 
	if(EVP_PKEY_derive(ctx, secret, &secret_len)<=0) handleErrors();
    
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(dh_params);
	EVP_PKEY_CTX_free(pctx);
    printf("SEGRETO: \t");
	BIO_dump_fp(stdout, (const char*)secret, secret_len);
    
	return secret;
}

//Codice del processo figlio
//Si occupa di stare in ascolto sul socket secondario di richieste di sfida che arrivano dal Server
void childCode(){
    struct sockaddr_in sv_addr_listen, opponent_addr;
    struct message match_m, m;
    char command;
    nice(0); 

    secondSd = setupSocket(cl_secondary_port);
    while(1){

        recv_message(secondSd, &match_m, (struct sockaddr*)&sv_addr_listen, FALSE, nonce);

        //nonce check
        if(nonceCheck(match_m.nonce, 1, getppid()) == 0)
            continue;

        //Sto sfidando io qualcuno o mi sta arrivando se hanno accettato la sfida o no ?
        if(match_m.opcode == ACCEPT_OPCODE){
            printf("Sfida accettata (child process)\n");
        }else if(match_m.opcode == MATCH_OPCODE){
            
            struct message reply_m;

            //clean input buffer
            fflush(stdin);

            kill(getppid(), SIGUSR2);
            printf("\nSei stato sfidato da: %d. Accetti? [y/n] : ", match_m.my_id);
            do{        
                scanf("%c", &command);
            }while(command != 'y' && command != 'n');
            sem_post(mutex_active_process);

            //Rispondo se ho accettato la richista o meno
            nonceInc(getppid());
            if(command == 'y'){
                printf("Hai accettato\n");
                pack_reply_message(&reply_m, 1, match_m.my_id);
            }
            else{
                printf("Hai rifiutato\n");
                pack_reply_message(&reply_m, 0, match_m.my_id);
            }


            send_message(&reply_m, &sv_addr_listen, secondSd, TRUE);

            //Richiesta accettata
            if(command == 'y'){
                //Waiting from server the public key of who hasked for the match
                struct message pubKey_m;
                recv_message(secondSd, &pubKey_m, (struct sockaddr*)&sv_addr_listen, FALSE, nonce);

                //nonce check
                if(nonceCheck(pubKey_m.nonce, 1, getppid()) == 0)
                    continue;

                printf("                                nonce:%d\n", nonce);

                //get sender public key
                printf("Public key of who asked for the match:\n%s\n", pubKey_m.pubKey);
                free(pubKey_m.pubKey);// Per ora lo cancelliamo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


                printf("Waiting for Battle request on port %d...\n", ntohs(cl_secondary_port));
                recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr, FALSE, 0);
                printf("Recived Battle request !!!!\n");
                
                ////
                // Negotiation
                size_t *secret_len = SECRET_SIZE; 
                printf("opponent addr %d", opponent_addr);
                unsigned char* secret = get_secret_ec(secret_len, cl_id, opponent_addr,0); //"0123456789"; //
                unsigned char* digest = hash(secret);
                //printf("Digest: %s\n", digest);
                ////

                pack_match_move_message(&m, 0);
                send_message(&m, &opponent_addr, secondSd, TRUE);
                free(m.cphtBuffer);
                free(m.tagBuffer);

                //Game start !!!
                printf("\nAdversary port: %d\n", ntohs(opponent_addr.sin_port));
                
                kill(getppid(), SIGUSR2);
                forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), secondSd, secondSd, FALSE, 100);
                
                printf("Press Enter to return to the main console ...\n");

                sem_post(mutex_active_process);
            }
        }else if(match_m.opcode == DENY_OPCODE){
            printf("Sfida rifiutata (child process)\n");
        }else{
            printf("Errore OPCODE da gestire\n");
        }
    }
}

EVP_PKEY* verifyCertificate(struct message m){

    int ret;
    char* cacert_file_name = "./CA/Cybersec CA_cert.pem";
    char* cacrl_file_name = "./CA/Cybersec CA_crl.pem";
    //char* certserver_file_name = "./CA/ServerCybersec_cert.pem"; //PER ORAAA

    // load the CA's certificate and the CRL(considero di averli già)
    FILE* cacert_file = fopen(cacert_file_name, "r");
    if(!cacert_file) handleErrors();
    X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    fclose(cacert_file);
    if(!cacert){ printf("cacert error\n") ; handleErrors();}

    FILE* crl_file = fopen(cacrl_file_name, "r");
    if(!crl_file) handleErrors();
    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    fclose(crl_file);
    if(!crl){ printf("crl error\n") ; handleErrors();}

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if(!store) { printf("store error\n") ; handleErrors();}
    ret = X509_STORE_add_cert(store, cacert);
    if(ret != 1){ printf("add cert error\n") ; handleErrors();}
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1){ printf("add crl error\n") ; handleErrors();}
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1){ printf("set flag error\n") ; handleErrors();}

    // get server's certificate:
 
   /* printf("m_sign_len %d e firmaaaa\n", m.sign_len);
    for(int i=0; i<m.sign_len; i++){
        printf("%c", m.sign[i]);
    }
    printf("\n");
    */
    unsigned char *tmpPtr;		//because d2i_X509 moves the ptr 
	tmpPtr = m.cert;
    int cert_len = m.cert_len;

    X509* cert = d2i_X509(NULL, (const unsigned char **)&tmpPtr, cert_len);
    if(!cert){printf("d2i error with code %d\n", ERR_get_error());} //handleErrors();}
    
    // verify the certificate:
    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { printf("Error: X509_STORE_CTX_new returned NULL\n"); handleErrors(); }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(!ret) { printf("Error: X509_STORE_CTX_init returned NULL\n"); handleErrors(); }
    ret = X509_verify_cert(certvfy_ctx);
    if(!ret) { printf("Error: X509_verify_cert returned NULL\n"); handleErrors(); }

    // print the successful verification to screen:
    char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
    printf("Certificate of %s released by %s verified successfully", tmp , tmp2);
    free(tmp);
    free(tmp2);

    EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
    if(server_pubkey==NULL) handleErrors();
    // riceve firmato
    // verifica 

    // deallocate data:
    //EVP_MD_CTX_free(md_ctx);
    X509_free(cert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(certvfy_ctx);
    
    
    printf("fine store :)");
    return server_pubkey;
}

int handleErrors(){
    printf("An error occourred \n");
    exit(1);
}

int main(int argc, char* argv[]){

    struct message m;
    struct sockaddr_in opponent_addr;

	// argument check
	if(argc < 4){
		printf("Not enough arguments. Try Again\n");
		printf("./client server_ip your_id server_port\n");
		exit(0);
	}

    //Initialasing semaphors
    mutex_active_process = sem_open("mutex_active_process", O_CREAT | O_EXCL, 0644, 0);
    if(mutex_active_process == SEM_FAILED) {
        //perror("semaphore initilization");
        sem_unlink("mutex_active_process");
        mutex_active_process = sem_open("mutex_active_process", O_CREAT | O_EXCL, 0644, 0);
        if(mutex_active_process == SEM_FAILED) {
            perror("semaphore initilization");
            exit(1);
        }
    }

    mutex_secondary_port = sem_open("mutex_secondary_port", O_CREAT | O_EXCL, 0644, 0);
    if(mutex_secondary_port == SEM_FAILED) {
        //perror("semaphore initilization");
        sem_unlink("mutex_secondary_port");
        mutex_secondary_port = sem_open("mutex_secondary_port", O_CREAT | O_EXCL, 0644, 0);
        if(mutex_secondary_port == SEM_FAILED) {
            perror("semaphore initilization");
            exit(1);
        }
    }
    
    //Getting values from comand line
	sv_ip = argv[1];
	sv_port = atoi(argv[2]); 
    cl_id = atoi(argv[3]);
    cl_main_port = atoi(argv[4]);
    
    cl_secondary_port = (argc>=6)? atoi(argv[5]): cl_main_port+100;


    // socket creation
	sd = socket(AF_INET, SOCK_DGRAM,0);	
	if(sd==-1){
		printf("Socket Creation Error: Client Stopping\n");
		exit(1);
	}
    

	// Client address creation
	memset(&cl_address,0, sizeof(cl_address)); // cleaning
	cl_address.sin_family = AF_INET;
	//hostlong from host byte order to network byte order
	cl_address.sin_addr.s_addr = INADDR_ANY; 
    cl_address.sin_port = htons(sv_port);

    pack_login_message(&m);
    printf("LOGIN MSG: %d\n", m.my_id);
    printf("MAIN PORTA: %d\n", cl_main_port);
    printf("SECONDARY PORTA: %d\n", cl_secondary_port);

    //server address creation
    sv_addr = setupAddress("127.0.0.1", sv_port);

    printf("Send Login request\n");
	send_message(&m, &sv_addr, sd, FALSE);

    struct message ack_login_m;
    printf("Waiting ACK...\n");
    recv_message(sd, &ack_login_m, (struct sockaddr*)&sv_addr, FALSE, nonce);

    printf("ACK received... Login Completed\n");
    if(ack_login_m.opcode != AUTH2_OPCODE){
        printf("Login Opcode Error %d\n", ack_login_m.opcode);
        exit(1);
    }

    printf("Cs = %d\n", ack_login_m.nonce);

    struct message m_response;
    pack_response_message(&m_response, ack_login_m.nonce);
    send_message(&m_response, &sv_addr, sd, FALSE);


    struct message ack_cert_m;
    printf("Waiting Cert and Response...\n");
    recv_message(sd, &ack_cert_m, (struct sockaddr*)&sv_addr, FALSE, 0);
    if(ack_cert_m.opcode != AUTH4_OPCODE){
        printf("Login Opcode Error %d\n", ack_cert_m.opcode);
        exit(1);
    }
    EVP_PKEY* server_pkey = verifyCertificate(ack_cert_m);

    // verifica
    int nonce_len = (unsigned int)floor(log10(cu))+1;
    char ch_cu[nonce_len];
    sprintf(ch_cu, "%u", cu);
    printf("provina\n");
    printf("cu: %u\n", cu);
    //char *test= "77"; //costante magica
	int ret;
    const EVP_MD* md = EVP_sha256();
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx) handleErrors();
	ret = EVP_VerifyInit(md_ctx, md);
	if(ret==0){ printf("Error verify init\n"); handleErrors();}
	ret = EVP_VerifyUpdate(md_ctx, ch_cu, nonce_len);
	if(ret==0){ printf("Error verify update\n"); handleErrors();}
	ret = EVP_VerifyFinal(md_ctx, ack_cert_m.sign, ack_cert_m.sign_len, server_pkey);
	if(ret!=1){ 
        printf("Error verify final con nonce_len %d e ch_cu \n", nonce_len);
        for(int i=0; i<nonce_len;i++)
            printf("%c",ch_cu[i]);
        handleErrors();
    }
	printf("Ca verified");
	EVP_PKEY_free(server_pkey);
	EVP_MD_CTX_free(md_ctx);


    size_t *secret_len = SECRET_SIZE; 
    printf("Ehiii");
    unsigned char* secret = get_secret_ec(secret_len, cl_id, sv_addr,2); //"0123456789"; //
    unsigned char* digest = hash(secret);
    //printf("Digest: %s\n", digest);

    /* Use digest of secret instead of secret to increase the entropy */

    printf("\033[1;32m");
	printf("Welcome to Forza4");
	printf("\033[0m"); 
    printf(": Enjoy with your friends! ");
    print_help();

    //to increse the other porcess nonce
    signal(SIGUSR1, updateNonce);

    //Creo processo figlio per gestire le richieste di partita
    pid_t pid;
    pid = fork();
	if(pid==-1){
		perror("Fork Error\n");
		exit(1);		
	}	

    //Child process
	if(pid==0){
        //Setup signals to interupt the child process
        signal(SIGUSR2, secondaryPortRequest);

        childCode();        
        return 0;
	}

    //Setup signal to interupt the father process
    signal(SIGUSR2, battleRequest);

    //Father process
    while(1){
        int cmd = get_cmd();

        switch(cmd){
            case CMD_EMPTY:
                //printf("\n");
                printf("%c[2K", 27);
                break;

            case CMD_UNKNOWN:
                printf("UNKNOWN COMMAND. Type !help to know the possible ones\n");
                break;
            case CMD_HELP:
                print_help();
                break;
            case CMD_LIST:

                sv_addr = setupAddress("127.0.0.1", sv_port);

                //nonce setup
                nonceInc(pid);
                pack_list_message(&m, cl_id);
    
                printf("Getting list of online users from the server \n");
                send_message(&m, &sv_addr, sd, TRUE);

                printf("Waiting ACK...\n");
                struct message ack_list;
                recv_message(sd, &ack_list, (struct sockaddr*)&sv_addr, TRUE, 0);

                //nonce check
                if(nonceCheck(ack_list.nonce, 1, pid) == 0)
                    continue;

                printf("ACK received");

                printf("List of the logged users:\n");
                for (int i = 0; i < ack_list.nOnlinePlayers; i++){
                    printf("- %d \n", ack_list.onlinePlayers[i]);
                }
                break;
            case CMD_MATCH:

                if(dest_id==cl_id){
                    printf("You can't rematch yourself!\n");
                    break;
                }
                nonceInc(pid);
                //("Nonce: %d\n", nonce);

                sv_addr = setupAddress("127.0.0.1", sv_port);

                //Sending request for match
                pack_match_message(&m);
                send_message(&m, &sv_addr, sd, TRUE);

                //Waiting request replay
                struct message ack_match_m;
                printf("Waiting Match ACK....\n");
                recv_message(sd, &ack_match_m, (struct sockaddr*)&sv_addr, FALSE, nonce);

                //nonce check
                if(nonceCheck(ack_match_m.nonce, 1, pid) == 0)
                    continue;

                //get reciver publick key
                printf("%s\n", ack_match_m.pubKey);
                free(ack_match_m.pubKey);

                int esito = (ack_match_m.flag==1)?ACCEPT_OPCODE:DENY_OPCODE;
                    
                printf("ACK Match received... Esito\n");
                if(esito== DENY_OPCODE){
                    printf("Partita rifiutata (main thread)\n");
                }else if(esito == ACCEPT_OPCODE){

                    kill(pid, SIGUSR2);
                    //aspetto che il porcesso figlio chouda il socket secondario
                    sem_wait(mutex_active_process);
                    secondSd = setupSocket(cl_secondary_port);

                    printf("Partita accettata (main thread)\n");
                    printf("Sending to port: %d\n", ack_match_m.dest_port);
                    opponent_addr = setupAddress("127.0.0.1", (int)ack_match_m.dest_port);

                    pack_match_move_message(&m, 0);
                    send_message(&m, &opponent_addr, secondSd, TRUE);
                    free(m.cphtBuffer);
                    free(m.tagBuffer);

                    ////
                    // Negoziazione
                    printf("opponent addr %d", opponent_addr);
                    unsigned char* secret = get_secret_ec(secret_len, cl_id, opponent_addr,1); //"0123456789"; //
                    unsigned char* digest = hash(secret);
                    //printf("Digest: %s\n", digest);

                    ////

                    printf("Waiting for confirm !!!!\n");
                    struct sockaddr* opponent_addr2;
                    recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr2, FALSE, nonce);

                    forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), secondSd, secondSd, TRUE, 100);
                    close(secondSd);
                    sem_post(mutex_secondary_port);

                    printf("Returning to the main console ...\n");
                    char temp[5];
                    fgets(temp, 5, stdin);
                }
                else{
                    printf("OPCODE Error da gestire\n");
                }
                
                fflush(stdin);
                break;
                
            case CMD_LOGOUT:

                //DA MODULARIZZARE
                //creazione indirizzo server
                memset(&sv_addr,0, sizeof(sv_addr)); //pulizia
                sv_addr.sin_family= AF_INET;
                sv_addr.sin_port = htons(sv_port);
                inet_pton(AF_INET, "127.0.0.1" , &sv_addr.sin_addr);

                nonceInc(pid);
                pack_logout_message(&m);

                send_message(&m, &sv_addr, sd, TRUE);

                printf("Waiting Logout ACK....\n");
                struct message ack_logout_m;
                recv_message(sd, &ack_logout_m, (struct sockaddr*)&sv_addr, FALSE, nonce);
                printf("Logout ACK received... Login Completed\n");
                if(ack_logout_m.opcode != ACK_OPCODE){
                    printf("Logout Opcode Error: %d\n", ack_logout_m.opcode);
                    exit(1);
                }

                //nonce check
                if(!nonceCheck(ack_logout_m.nonce, 1, pid))
                    continue;

                close(sd);
                close(secondSd);
                exit(0);
        }   
    }

    return 1;
}