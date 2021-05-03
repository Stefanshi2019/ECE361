all: server client
server: server.c common.h
	gcc -o server server.c -lpthread -g
client: client.c common.h
	gcc -o client client.c -lpthread -g
clean:  
	rm server client
