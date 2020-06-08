CC=gcc
CFLAGS = -Wall


server: server.o receive.o send.o utilityFile.o -lcrypto
	$(CC) $(CFLAGS) $^ -o server 
	rm *.o

server.o: server.c
	$(CC) $(CFLAGS) -c server.c -o $@



client: client.o forza4Engine.o receive.o send.o list.o
	$(CC) $(CFLAGS) $^ -o client -pthread -lcrypto
	rm *.o
	
client.o: client.c
	$(CC) $(CFLAGS) -c client.c -o client.o

%.o : def/%.c
	gcc -c $< -o $@


clear: 
	rm *.o
