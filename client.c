#include<sys/types.h>
#include<sys/socket.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<semaphore.h> 
#include<unistd.h>
#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<signal.h>
#include "header/forza4Engine.h"
#ifndef MESSAGE_H
    #define MESSAGE_H
    #include"header/message.h"
#endif
#include "header/send.h"
#include "header/receive.h"
#include "header/list.h"

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

void pack_login_message(struct message* aux){

	aux->opcode = LOGIN_OPCODE;
    aux->my_id = cl_id;
    aux->my_listen_port = cl_secondary_port;
}

void pack_logout_message(struct message* aux){

	aux->opcode = LOGOUT_OPCODE;
    aux->my_id = cl_id;
}

void pack_match_move_message(struct message* aux, uint8_t column){
    aux->opcode = MATCH_MOVE_OPCODE;
    aux->my_id = cl_id;
    aux->addColumn = column;
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
}

void pack_match_message(struct message* aux){

    aux->opcode = MATCH_OPCODE;
    aux->my_id = cl_id;
    aux->dest_id = htons(dest_id);
    printf("Dest id pack match: %u, %u\n", dest_id, aux->dest_id);

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
    int ret = bind(secondSd, (struct sockaddr*)&cl_listen_addr, sizeof(cl_listen_addr));
    if(ret!=0){
        printf("Binding Error: the port %d is already in use\n", port);			
        exit(1);			
    }

    return secondSd;
}



void battleRequest(){

    sem_wait(mutex_active_process);

}



//Signal per intrrompere l'esecuzione del processo figlio
void secondaryPortRequest(){
    printf("eeentroooo innnnnnn Tamadreeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee!!\n");

    close(secondSd);

    //riattivo il processo padre
    sem_post(mutex_active_process);

    sem_wait(mutex_secondary_port);
    printf("Tamadreeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee!!\n");
    secondSd = setupSocket(cl_secondary_port);
    printf("Si ricomincia aaaa afaaaaaaaaaaaaaaa        %d\n", secondSd);
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

        printf("Si ricomincia aaaa afaaaaaaaaaaaaaaa        %d\n", secondSd);
        recv_message(secondSd, &match_m, (struct sockaddr*)&sv_addr_listen);


        //Sto sfidando io qualcuno o mi sta arrivando se hanno accettato la sfida o no ?
        if(match_m.opcode == ACCEPT_OPCODE){
            printf("Sfida accettata (child process)\n");
        }else if(match_m.opcode == MATCH_OPCODE){
            
            struct message reply_m;

            //clean input buffer
            fflush(stdin);

            kill(getppid(), SIGUSR1);
            printf("\nSei stato sfidato da: %d. Accetti? [y/n] : ", match_m.my_id);
            do{        
                scanf("%c", &command);
            }while(command != 'y' && command != 'n');
            sem_post(mutex_active_process);

            //Rispondo se ho accettato la richista o meno
            if(command == 'y'){
                printf("Hai accettato\n");
                pack_reply_message(&reply_m, 1, match_m.my_id);
            }
            else{
                printf("Hai rifiutato\n");
                pack_reply_message(&reply_m, 0, match_m.my_id);
            }
            send_message(&reply_m, &sv_addr_listen, secondSd);

            //Richiesta accettata
            if(command == 'y'){
                printf("Waiting for Battle request on port %d...\n", ntohs(cl_secondary_port));
                recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);
                printf("Recived Battle request !!!!\n");
                pack_match_move_message(&m, 0);
                send_message(&m, &opponent_addr, secondSd);

                //Game start !!!
                printf("\nAdversary port: %d\n", ntohs(opponent_addr.sin_port));
                
                kill(getppid(), SIGUSR1);
                forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), secondSd, secondSd, FALSE);
                
                printf("Press Enter to return to the main console ...\n");

                sem_post(mutex_active_process);
            }
        }else{
            printf("Errore OPCODE da gestire\n");
        }
    }
}




int main(int argc, char* argv[]){

    struct message m, listRequestMessage;
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
	cl_address.sin_addr.s_addr = htonl(INADDR_ANY); 
    cl_address.sin_port = htons(sv_port);

    pack_login_message(&m);
    printf("MAIN PORTA: %d\n", cl_main_port);
    printf("SECONDARY PORTA: %d\n", cl_secondary_port);

    //server address creation
    sv_addr = setupAddress("127.0.0.1", sv_port);

    printf("Send Login request\n");
	send_message(&m, &sv_addr, sd);

    struct message ack_login_m;
    printf("Waiting ACK...\n");
    recv_message(sd, &ack_login_m, (struct sockaddr*)&sv_addr);

    printf("ACK received... Login Completed\n");
    if(ack_login_m.opcode != ACK_OPCODE){
        printf("Login Opcode Error\n");
        exit(1);
    }
    printf("\033[1;32m");
	printf("Welcome to Forza4");
	printf("\033[0m"); 
    printf(": Enjoy with your friends! ");
    print_help();


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
    signal(SIGUSR1, battleRequest);

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
                
                //printf("placeholder list\n");
                pack_list_message(&listRequestMessage, cl_id);
                listRequest(listRequestMessage, sv_addr, sd);
                break;
            case CMD_MATCH:

                sv_addr = setupAddress("127.0.0.1", sv_port);

                //Sending request for match
                pack_match_message(&m);
                send_message(&m, &sv_addr, sd);

                //Waiting request replay
                struct message ack_match_m;
                printf("Waiting Match ACK....\n");
                recv_message(sd, &ack_match_m, (struct sockaddr*)&sv_addr);

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
                    send_message(&m, &opponent_addr, secondSd);

                    printf("Waiting for confirm !!!!\n");
                    recv_message(secondSd, &m, (struct sockaddr*)&opponent_addr);

                    forza4Engine("127.0.0.1", ntohs(opponent_addr.sin_port), secondSd, secondSd, TRUE);
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

                pack_logout_message(&m);

                send_message(&m, &sv_addr, sd);
                struct message ack_logout_m;
                printf("Waiting Logout ACK....\n");
                recv_message(sd, &ack_logout_m, (struct sockaddr*)&sv_addr);
                printf("Logout ACK received... Login Completed\n");
                if(ack_logout_m.opcode != ACK_OPCODE){
                    printf("Logout Opcode Error: %d\n", ack_logout_m.opcode);
                    exit(1);
                }
                exit(0);
        }   
    }

    return 1;
}