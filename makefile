CC=gcc
CFLAGS = -Wall


server: server.o receive.o send.o utilityFile.o symEncript.o
	$(CC) $(CFLAGS) $^ -o server -lcrypto -lm
	rm *.o

server.o: server.c
	$(CC) $(CFLAGS) -c server.c -o $@



client: client.o forza4Engine.o receive.o send.o symEncript.o utilityFile.o
	$(CC) $(CFLAGS) $^ -o client -pthread -lcrypto -lm 
	rm *.o
	
client.o: client.c
	$(CC) $(CFLAGS) -c client.c -o client.o

%.o : def/%.c
	gcc -c $< -o $@


clear: 
	rm *.o
