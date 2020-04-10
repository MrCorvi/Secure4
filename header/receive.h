int deserialize_message(char* buffer, struct message *aux);

int recv_message(int socket, struct message* message, struct sockaddr* mitt_addr);
