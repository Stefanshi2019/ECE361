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
#include <pthread.h>

#include "common.h"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
void* get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int in_session = 0;

void* receive_message(void* arg){
	//pthread_mutex_lock(&lock);
	int* sockfd = (int*) arg;
	int numbytes;
	char buf[100];
	while(1){
		//pthread_mutex_lock(&lock);
		if ((numbytes = recv(*sockfd, buf, MAXDATASIZE - 1, 0)) == -1) {
			perror("client: recv message");
			return NULL;
		}
		buf[numbytes] = '\0';
		message m = break_message(buf);
		if(m.type == MESSAGE || m.type == DM)
			printf("%s\n", m.data);
		else if(m.type == JN_ACK){
			printf("Join Session %s Successfully!\n", m.data);
			in_session = 1;
		}
		else if(m.type == JN_NAK){
			printf("Join Session %s Failed!\n", m.data);
		}
		else if(m.type == NS_ACK){
			printf("Create Session Successfully!\n");
			in_session = 1;
		}
		else if(m.type == NS_NAK){
			printf("Create Session Failed!\n");
		}
		else if(m.type == QU_ACK){
			//printf("Received: %s\n", m.data);
			char* temp = strtok(m.data, ",");
			while(temp != NULL){
				printf("User: %s, Session: %s\n", temp, strtok(NULL, ","));
				temp = strtok(NULL, ",");
			}
		}
		else if(m.type == QUIT_ACK){
			printf("Quit Successfully\n");
			exit(0);
		}
		
	}
	//pthread_mutex_unlock(&lock);
	return NULL;
}
	

int main(int argc, char const *argv[]){
	
	int sockfd, numbytes;
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	pthread_t receive_thread;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	char input[500];
	char whole_input[500];
	char cmd[100];
	char ID[100];
	char password[100];
	char addr[100];
	char port[100];
	char sessionID[100];
	char dm[500];
	int active = 0;
	//int in_session = 0;

	while(1){
		fgets(input, 499, stdin);
		input[strcspn(input, "\n")] = 0;
		strcpy(whole_input, input);
		strcpy(cmd, strtok(input, " "));
		if(strcmp(cmd, "/login") == 0){
			strcpy(ID, strtok(NULL, " "));
			strcpy(password, strtok(NULL, " "));
			strcpy(addr, strtok(NULL, " "));
			strcpy(port, strtok(NULL, " "));
			//printf("%s\n", addr);
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
			//printf("client: connecting to %s\n", s);
			freeaddrinfo(servinfo);
			
			message m = new_message(LOGIN, sizeof(password), ID, password);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);

			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send login");
				return 1;
			}
			//printf("Client sent ID and password\n");
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
				pthread_create(&receive_thread, NULL, receive_message, &sockfd);
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
			in_session = 0;
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send logout");
				return 1;
			}
			pthread_cancel(receive_thread);
			printf("Logout Request Sent\n");
		}
		else if(strcmp(cmd, "/joinsession") == 0){
			//printf("entered join\n");
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
//			if(in_session == 1){
//				printf("Attempt Failed: Already In A Session!\n");
//				continue;
//			}
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
			printf("Join Request Sent\n");
			/*if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
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
			}*/
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
			printf("Leave Request Sent\n");
			//pthread_cancel(receive_thread);
		}
		else if(strcmp(cmd, "/createsession") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
//			if(in_session == 1){
//				printf("Attempt Failed: Already In A Session!\n");
//				continue;
//			}
			strcpy(sessionID, strtok(NULL, " "));
			message m = new_message(NEW_SESS, strlen(sessionID), ID, sessionID);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send create");
				return 1;
			}
			//printf("Create Request Sent\n");
			/*if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv create");
				return 1;
			}
			buf[numbytes] = '\0';
			//printf("%s\n", buf);
			m = break_message(buf);
			//printf("%d\n", m.type);
			if(m.type == NS_ACK){
				printf("Create Session %s Successfully!\n", sessionID);
				in_session = 1;
				//pthread_create(&receive_thread, NULL, receive_message, &sockfd);
			}
			else if(m.type == NS_NAK){
				printf("Create Session %s Failed!\n", sessionID);
			}*/
		}
		else if(strcmp(cmd, "/list") == 0){
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
			printf("Query Request Sent\n");
			/*if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv list");
				return 1;
			}
			//printf("Query List Received\n");
			buf[numbytes] = '\0';
			//printf("Received: %s\n", buf);
			m = break_message(buf);
			//printf("Received: %s\n", m.data);
			if(m.type == QU_ACK){
				//printf("Received: %s\n", m.data);
				char* temp = strtok(m.data, ",");
				while(temp != NULL){
					printf("User: %s, Session: %s\n", temp, strtok(NULL, ","));
					temp = strtok(NULL, ",");
				}
			}*/
		}
		else if(strcmp(cmd, "/quit") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			message m = new_message(QUIT, 0, ID, "");
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send quit");
				return 1;
			}
			
			//printf("Quit Request Sent\n");
			/*if((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
				perror("client: recv quit");
				return 1;
			}
			buf[numbytes] = '\0';
			m = break_message(buf);
			if(m.type == QUIT_ACK){
				printf("Quit Successfully\n");
				return 0;
			}
			else
				printf("Quit Failed\n");*/
		}
		else if(strcmp(cmd, "/dm") == 0){
			if(active == 0){
				printf("Attempt Failed: Must Log In First!\n");
				continue;
			}
			strcpy(dm, strtok(NULL, "\n"));
			message m = new_message(DM, strlen(dm), ID, dm);
			//printf("sent dm: %s\n", dm);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			//printf("form\n");
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: send dm");
				return 1;
			}
		}
		else{
			if(in_session == 0){
				printf("Attempt Failed: Unknown Command!\n");
				continue;
			}
                        if(whole_input == NULL || whole_input == "\n" || whole_input == "")
                            continue;
			//printf("input: %s\n", whole_input);
			message m = new_message(MESSAGE, strlen(whole_input), ID, whole_input);
			char sp[2000];
			int len = 0;
			form_message(m, sp, &len);
			//printf("%s\n", sp);
			if((numbytes = send(sockfd, sp, len, 0)) == -1){
				perror("client: message");
				return 1;
			}
			//printf("Message Sent\n");
		}
	}
	close(sockfd);
	return 0;
}


