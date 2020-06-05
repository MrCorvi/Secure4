#include "../header/list.h"

void pack_list_message(struct message* aux, uint32_t id, uint32_t nonce){

	aux->opcode = LIST_OPCODE;
    //For now, the id is given by an input !!!!!!!!!!!!!!!!!
    //printf("Input your ID: ");
    //scanf("%d", &id);
    aux->my_id = id;
    aux->nonce = nonce;
}

struct message pack_list_ack(){
    struct message aux;
    aux.opcode = ACK_OPCODE;
    aux.nOnlinePlayers = 3;
    return aux;
}

void listRequest(struct message m, struct sockaddr_in sv_addr, int sd, pid_t pid){
    struct message ack_list;
    
    printf("Getting list of online users from the server \n");
    send_message(&m, &sv_addr, sd);
    printf("Waiting ACK...\n");
    recv_message(sd, &ack_list, (struct sockaddr*)&sv_addr);

    //nonce check
    //if(nonceCheck(m.nonce, 1, pid) == 0)
    //    return;

    printf("ACK received");

    printf("List of the logged users:\n");
    for (int i = 0; i < ack_list.nOnlinePlayers; i++){
        printf("- %d \n", ack_list.onlinePlayers[i]);
    }
}