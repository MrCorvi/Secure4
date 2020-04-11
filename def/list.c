#include "../header/list.h"

void pack_list_message(struct message* aux){

	aux->opcode = LIST_OPCODE;
    //For now, the id is given by an input !!!!!!!!!!!!!!!!!
    uint32_t id;
    printf("Input your ID: ");
    scanf("%d", &id);
    printf("\n");
    aux->my_id = id;
}

void listRequest(struct message m, struct sockaddr_in sv_addr, int sd){
    printf("Getting list of online users from the server \n");
    send_message(&m, &sv_addr, sd);
    struct message ack_login_m;
    printf("Waiting ACK...\n");
    recv_message(sd, &ack_login_m, (struct sockaddr*)&sv_addr);
    printf("ACK received... Login Completed\n");
}