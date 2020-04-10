int serialize_message(void* buffer, struct message *aux);

void send_message(struct message *mex, struct sockaddr_in * dest_addr,int socket);
