all: server client
server: server.c
	gcc -g -lpthread server.c -o server
deliver: deliver.c
	gcc -g -lpthread client.c -o deliver
clean:  
	rm server client
