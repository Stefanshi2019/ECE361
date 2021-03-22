#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define MAXDATASIZE 100

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
	QU_ACK
}message_type;

typedef struct message{
	unsigned int type;
	unsigned int size;
	unsigned char source[MAXDATASIZE];
	unsigned char data[MAXDATASIZE];
}message;

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

void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char const *argv[]){
	
	int sockfd, numbytes;
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	char input[500];
	char cmd[100];
	char ID[100];
	char password[100];
	char addr[100];
	char port[100];
	char sessionID[100];
	int active = 0;
	int in_session = 0;

	while(1){
		//printf("In while\n");
		//scanf("%s %s %s %s %s", cmd, ID, password, addr, port);
		//printf("%s\n", cmd);
		gets(input);
		strcpy(cmd, strtok(input, " "));
		printf("%s\n", cmd);
		if(strcmp(cmd, "/login") == 0){
			strcpy(ID, strtok(NULL, " "));
			strcpy(password, strtok(NULL, " "));
			strcpy(addr, strtok(NULL, " "));
			strcpy(port, strtok(NULL, " "));
			//printf("In login\n");
			if ((rv = getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
				fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
				return 1;
			}
			for(p = servinfo; p != NULL; p = p->ai_next) {
				if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
					perror("client: socket");
					continue;
				}
				if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
					close(sockfd);
					perror("client: connect");
					continue;
				}

				break; 
			}
			if(p == NULL){
				fprintf(stderr, "client: failed to connect\n");
				return 1;
			}
			inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof(s));
			printf("client: connecting to %s\n", s);
			freeaddrinfo(servinfo);
			
			message m = new_message(LOGIN, sizeof(password), ID, password);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);

			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send login");
				return 1;
			}
			printf("Client sent ID and password\n");
			if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv login");
				return 1;
			}
			buf[numbytes] = '\0';
			//printf("%s\n", buf);
			m = break_message(buf);
			//printf("%d\n", m.type);
			if(m.type == LO_ACK){
				printf("Login Successfully!\n");
				active = 1;
			}
			else if(m.type == LO_NAK){
				if(strcmp(m.data, "0") == 0)
					printf("Login Failed: Wrong Username or Password!\n");
				else if(strcmp(m.data, "1") == 0)
					printf("Login Failed: User Already Logged In\n");

			}
		}
		else if(strcmp(cmd, "/logout") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			message m = new_message(EXIT, 0, ID, "");
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			active = 0;
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send logout");
				return 1;
			}
			printf("Logout request sent\n");
		}
		else if(strcmp(cmd, "/joinsession") == 0){
			//printf("entered join\n");
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			if(in_session == 1){
				printf("Attempt Failed: Already In A Session!\n");
				continue;
			}
			strcpy(sessionID, strtok(NULL, " "));
			//printf("%s\n", sessionID);
			message m = new_message(JOIN, strlen(sessionID), ID, sessionID);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send join");
				return 1;
			}
			printf("Join request sent\n");
			if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv join");
				return 1;
			}
			buf[numbytes] = '\0';
			//printf("%s\n", buf);
			m = break_message(buf);
			//printf("%d\n", m.type);
			if(m.type == JN_ACK){
				printf("Join Session %s Successfully!\n", m.data);
				in_session = 1;
			}
			else if(m.type == JN_NAK){
				printf("Join Session %s Failed!\n", m.data);
			}
		}
		else if(strcmp(cmd, "/leavesession") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			if(in_session == 0){
				printf("Attempt Failed: Must Be In A Session First!\n");
				continue;
			}
			//printf("entered leave session\n");
			message m = new_message(LEAVE_SESS, 0, ID, "");
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send leave");
				return 1;
			}
			in_session = 0;
			printf("Leave Session request sent\n");
		}
		else if(strcmp(cmd, "/createsession") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			if(in_session == 1){
				printf("Attempt Failed: Already In A Session!\n");
				continue;
			}
			strcpy(sessionID, strtok(NULL, " "));
			message m = new_message(NEW_SESS, strlen(sessionID), ID, sessionID);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send create");
				return 1;
			}
			printf("Create request sent\n");
			if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv create");
				return 1;
			}
			buf[numbytes] = '\0';
			//printf("%s\n", buf);
			m = break_message(buf);
			//printf("%d\n", m.type);
			if(m.type == NS_ACK){
				printf("Create Session %s Successfully!\n", m.data);
				in_session = 1;
			}
			else if(m.type == NS_NAK){
				printf("Create Session %s Failed!\n", m.data);
			}
		}
		/*else if(strcmp(cmd, "/list") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			message m = new_message(QUERY, 0, ID, "");
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send list");
				return 1;
			}
			printf("List request sent\n");
			
		}*/
	}

	close(sockfd);
	return 0;
}


