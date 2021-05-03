#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXDATASIZE 100
#define BACKLOG 10
#define MAXCLIENT 10
#define MAXSESSION 10

enum{
	LOGIN,
	LO_ACK,
	LO_NAK,
	EXIT,
	JOIN,
	JN_ACK,
	JN_NAK,
	LEAVE_SESS,
	NEW_SESS,
	NS_ACK,
        NS_NAK,
	MESSAGE,
	QUERY,
	QU_ACK,
	QUIT,
	QUIT_ACK,
        DM
}message_type;

typedef struct client{
	int sockfd;
        int loggedin;
        int session_id[MAXSESSION];
	char ID[100];
	char password[100];
	pthread_t p;
	struct client* next;
}client;

typedef struct message{
	unsigned int type;
	unsigned int size;
	unsigned char source[MAXDATASIZE];
	unsigned char data[MAXDATASIZE];
}message;

typedef struct session{
	int session_id;
	char session_name[100];
	// clients can be accessed directly by user id
	struct client* clients[MAXCLIENT];
	int num_users;
}session;

message new_message(unsigned int type, unsigned int size, unsigned char* source, unsigned char* data){
	message res;
	res.type = type;
	res.size = size;
	strcpy(res.source, source);
	strcpy(res.data, data);
	return res;
}

void form_message(message p, char* sp, int * len){
	memset(sp, 0, 2000);
	int header = sprintf(sp, "%d:%d:%s:%s:", p.type, p.size, p.source, p.data);
	*len = header;
}

message break_message(char* sp){
	message res;
	res.type = atoi(strtok(sp, ":"));
	res.size = atoi(strtok(NULL, ":"));
	strcpy(res.source, strtok(NULL, ":"));

	if(res.size > 0)
		strcpy(res.data, strtok(NULL, ":"));
	else
		strcpy(res.data, "");
	return res;
}
