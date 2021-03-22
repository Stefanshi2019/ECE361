#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
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
	QU_ACK
}message_type;

typedef struct client{
	int sockfd;
        int loggedin;
        int session_id;
	char ID[100];
	char password[100];
	pthread_t p;
	struct client* next;
}client;

int num_con = 0;
client *active_client = NULL;

// a client_list which stores all potential clients that may access the server, dynamically allocated with num_clients
static client client_list[MAXCLIENT];
int num_clients;

pthread_mutex_t login_lock = PTHREAD_MUTEX_INITIALIZER;
// function definitions
    
typedef struct message{
	unsigned int type;
	unsigned int size;
	unsigned char source[MAXDATASIZE];
	unsigned char data[MAXDATASIZE];
}message;

// =============================================================================
// newly added stuff
pthread_mutex_t session_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct session{
    int session_id;
    char session_name[100];
// clients can be accessed directly by user id
    struct client* clients[MAXCLIENT];
    int num_users;
}session;

// the index to session_list is session id
static session session_list[MAXSESSION];

void initialize_session_list(){
	pthread_mutex_lock(&session_lock);
	for(int i=0; i<MAXSESSION; ++i){
		session_list[i].session_id = i;
		session_list[i].num_users = 0;
                memset(session_list[i].session_name, '\0', 100);
		for(int j=0; j<MAXCLIENT; ++j){
			session_list[i].clients[j] = NULL;
		}
	}
	pthread_mutex_unlock(&session_lock);
}

void print_session_info(int s_id, int c_id){
    for(int i = 0; i < MAXCLIENT; i++){
        if(client_list[i].loggedin == 1 && client_list[i].session_id == s_id)
            printf("User %s is in\n", session_list[s_id].clients[i]->ID);
    }
}

int create_session(char* session_name){
    // find the smallest session with no users
    pthread_mutex_lock(&session_lock);
    for(int i=0; i<MAXSESSION; ++i){
        if(session_list[i].num_users == 0){
            strcpy(session_list[i].session_name, session_name);
            pthread_mutex_unlock(&session_lock);
            printf("New session create: name %s, s_id %d\n", session_name, i);
            return i;
        }
    }
    pthread_mutex_lock(&session_lock);
    printf("All sessions used\n");
    return -1;
}

int find_session(char* session_name){
    pthread_mutex_lock(&session_lock);
    for(int i=0; i<MAXSESSION; ++i){
        if(strcmp(session_list[i].session_name, session_name) == 0){
            pthread_mutex_unlock(&session_lock);
            printf("Session found: %s, s_id %s\n", session_name, i);
            return i;
        }
    }
    pthread_mutex_unlock(&session_lock);
    printf("Session not found\n");
    return -1;
}

int join_session(int s_id, int c_id){
    
        pthread_mutex_lock(&session_lock);
    // for all functions, 1 means error is raised
    // validity of user_index is already handled
        if(s_id >= MAXSESSION || s_id < 0){
            pthread_mutex_unlock(&session_lock);
            printf("Join Session %d Failed: Session ID Invalid\n", s_id);
            return 1;
        }
        if(session_list[s_id].num_users >= MAXCLIENT){
            pthread_mutex_unlock(&session_lock);
            printf("Join Session %d Failed: Session Full\n", s_id);
            return 1;
        }
        if(client_list[c_id].session_id != -1){
            pthread_mutex_unlock(&session_lock);
            printf("Join Session %d Failed: Already Joined a Session\n", s_id);
            return 1;
        }
        client_list[c_id].session_id = s_id;
        session_list[s_id].clients[c_id] = &(client_list[c_id]);
        session_list[s_id].num_users++;
        printf("Join Session %d Successfully: User %d\n", s_id, c_id);
        //print_session_info(s_id, c_id);
        pthread_mutex_unlock(&session_lock);
        return 0;
}

int leave_session(int c_id){
	pthread_mutex_lock(&session_lock);
	int s_id = client_list[c_id].session_id;
	if(s_id == -1){
		pthread_mutex_unlock(&session_lock);
		perror("user not joined to any session");
		return 1;
	}
	client_list[c_id].session_id = -1;
	session_list[s_id].clients[c_id] = NULL;
	session_list[s_id].num_users--;
        if(session_list[s_id].num_users < 0){
            pthread_mutex_unlock(&session_lock);
            perror("theres a goddamn problem dawwwg");
            return 1;
        }
        if(session_list[s_id].num_users == 0)
            memset(session_list[s_id].session_name, '\0', 100);
	printf("user %d left session %d\n", c_id, s_id);
	pthread_mutex_unlock(&session_lock);
	return 0;
    
}
// ====================================================================================================

//initialize client_list
void initialize_client_list(){
    // read file 
	FILE *fp = fopen("userdetail.txt", "r");
	if(fp == NULL)
	    perror("fp");
	//printf("1\n");
	int login = 0;
	int r = 0;
	char ID[50][MAXCLIENT];
	char password[50][MAXCLIENT];
	int client_count = 0;
	while(r != EOF){
		memset(ID[client_count], '\0', 1);
		memset(password[client_count], '\0', 1);
		r = fscanf(fp, "%s %s\n", client_list[client_count].ID, client_list[client_count].password);

		int ID_len = strlen(client_list[client_count].ID) / sizeof(char);
		printf("id len is %d\n", ID_len);
			
		//client_list[client_count].ID
		    printf("%s... \n", password[client_count]);
		   // printf("%s %s\n", ID[client_count], password[client_count]);
		    client_count++;
	    
	}

	num_clients = client_count - 1;
	//    client_list = malloc(num_clients * sizeof(struct client));
	for(int i=0; i<num_clients; ++i){
	//        client_list[i].ID = ID[i];
	//        client_list[i].password = password[i];
		client_list[i].loggedin = 0;
		client_list[i].sockfd = -1;
		client_list[i].session_id = -1;
		client_list[i].p = -1;
		client_list[i].next = NULL;
	}
	for(int i=0; i<num_clients; ++i){
		printf("ID %s, pass %s, loggedin %d\n", client_list[i].ID, client_list[i].password, client_list[i].loggedin);
	}

}

void* handle_request(void* arg);
void client_login(client* c, message m, int* s);
void client_exit(client* c, message m, int* s);
void client_join(client* c, message m);
void client_leave_sess(client* c, message m);
void client_new_sess(client* c, message m);
bool check_login(struct message* m);

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

void sigchld_handler(int s){
	int saved_errno = errno;
	while(waitpid(-1, NULL, WNOHANG) > 0);
	errno = saved_errno;
}

void *get_in_addr(struct sockaddr *sa){
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}




int main(int argc, char const *argv[]){
	initialize_client_list();
	initialize_session_list();
        for(int i=0; i<num_clients; ++i){
                printf("ID %s, pass %s, loggedin %d\n", client_list[i].ID, client_list[i].password, client_list[i].loggedin);
        }
        
        for(int i=0; i<num_clients; ++i){
                printf("ID %s, pass %s, loggedin %d\n", client_list[i].ID, client_list[i].password, client_list[i].loggedin);
        }
        
        
        for(int i=0; i<num_clients; ++i){
                printf("ID %s, pass %s, loggedin %d\n", client_list[i].ID, client_list[i].password, client_list[i].loggedin);
        }
        
        
	int sockfd, new_sockfd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; 
	socklen_t sin_size;
	struct sigaction sa;
	int yes = 1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if(rv = getaddrinfo(NULL, argv[1], &hints, &servinfo) != 0){
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	for(p = servinfo; p != NULL; p = p->ai_next){
		sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
		if(sockfd == -1){
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if(bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1){
			close(sockfd);
			perror("server: bind");
			continue;
		}
		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: got connection from %s\n", s);

	while(1){
		client* c = (client*) malloc(sizeof(client));
		sin_size = sizeof(their_addr);
		new_sockfd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_sockfd == -1) {
			perror("accept");
			continue;
		}
		c->sockfd = new_sockfd;
		inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s));
		printf("server: got connection from %s\n", s);

		pthread_create(&(c->p), NULL, handle_request, (void*)c);
	}
	close(sockfd);
	return 0;
}


int find_client_index(struct message* m){
	char* src = m->source;
	//printf("src name is %s\n", m->source);
	for(int i=0; i<num_clients; ++i){
		//printf("each potential client name is %s, src name is %s\n", client_list[i].ID, src);
		if(strcmp(client_list[i].ID, m->source) == 0){
			return i;
		}
	}
	return -1;
}

bool check_login(struct message* m){
    
	int i = find_client_index(m);
	if(i == -1)
		return false;
	return client_list[i].loggedin;
}

void* handle_request(void* arg){
	client* c = (client*) arg;
	int numbytes;
	char buf[MAXDATASIZE];
	int active = 0;
	
	while(1){
		//printf("ready to receive\n");
		memset(buf, 0, MAXDATASIZE);
		if((numbytes = recv(c->sockfd, buf, MAXDATASIZE - 1, 0)) == -1){
			perror("server: handle_request");
			return NULL;
		}
		//printf("%d\n", numbytes);
		buf[numbytes] = '\0';
		if(numbytes == 0) //EXIT
			break;
		//printf("server received buf: %s\n", buf);
		message m = break_message(buf);
		
		// if the client is not logged in but trying to do some fancy stuff, 
		// which fails automatically redirect to client login
		//client_login(c, m);
	    	//printf("active: %d\n", active);
		if(m.type == LOGIN && active == 0){
			client_login(c, m, &active);
			//printf("active: %d\n", active);
		}
		else if (m.type == EXIT){
			client_exit(c, m, &active);
			if(active == 0)
				break;
		}
		else if(m.type == JOIN)
			client_join(c, m);
		else if (m.type == LEAVE_SESS)
			client_leave_sess(c, m);
		else if(m.type == NEW_SESS)
			client_new_sess(c, m);
	}
	close(c->sockfd);
	return NULL;
}

void client_login_failed(client* c, message m, char* t){
	message m_ack = new_message(2, 1, "server", t);
	char sp[2000];
	int len = 0;
	form_message(m_ack, sp, &len);
	if(send(c->sockfd, sp, len, 0) == -1){
		perror("send login_nack");
		return;
	}
}

void client_login_successful(client* c, message m){

	message m_ack = new_message(1, 0, "server", "");
	char sp[2000];
	int len = 0;
	form_message(m_ack, sp, &len);
	if(send(c->sockfd, sp, len, 0) == -1){
		perror("send login_ack");
		return;
	}
}

void client_login(client* c, message m, int* s){
    
    // if havent logged in yet, return login successful
	bool  corret_user_psd = false;

	int i = find_client_index(&m);
        if(i == -1){
		printf("Login Failed: Username Does Not Exist!\n");
		client_login_failed(c, m, "0");
		//*s = 1;
		return;
        }
    
        if(client_list[i].loggedin == 1 && m.type == LOGIN){
		printf("Login Failed: User Already Logged In\n");
		client_login_failed(c, m, "1");
		//*s = 1;
		return;
        }

        if(strcmp(client_list[i].password, m.data) != 0){
		printf("Login Failed: Wrong Password!\n");
		client_login_failed(c, m, "0");
		//*s = 1;
		return;
           
        }

        if(m.type == LOGIN){
		printf("Login Successfully!\n");
		client_list[i].loggedin = 1;
		*s = 1;
		client_login_successful(c, m);
		return;
        }
}

void client_exit(client* c, message m, int* s){
	int i = find_client_index(&m);
	if(client_list[i].loggedin == 1){
		client_list[i].loggedin = 0;
		*s = 0;
		printf("Logout Successfully!\n");
		close(c->sockfd);
		//free(c);
		return;
	}
	return;
}

void client_join(client* c, message m){
	int c_id = find_client_index(&m);
	int s_id = find_session(m.data);
	int err = join_session(s_id, c_id);
    	printf("err: %d\n", err);
    	// if log in success
	if(!err){
		//int length = snprintf( NULL, 0, "%d", s_id );
		//char str[5];
		//snprintf(str, 2, "%d", s_id);
		
		message m_ack = new_message(JN_ACK, 5, "server", m.data);
		char sp[2000];
		int len = 0;
		form_message(m_ack, sp, &len);
        	if(send(c->sockfd, sp, len, 0) == -1){
		        perror("send login_ack");
		        return;
        	}
        
    	}
	// if log in failed
    	else{
		//char str[5];
		//snprintf(str, 2, "%d", s_id);

		message m_ack = new_message(JN_NAK, 5, "server", m.data);
		char sp[2000];
		int len = 0;
		form_message(m_ack, sp, &len);
		if(send(c->sockfd, sp, len, 0) == -1){
			perror("send login_nak");
			return;
        	}
        
    	}
	printf("client_join performed\n");
	return;
}

void client_leave_sess(client* c, message m){
    (void)c;
        int c_id = find_client_index(&m);
        int err = leave_session(c_id);
        
        if(!err){
            
            printf("leave session sucess\n");
        }
        else{
            printf("leave session failed\n");
        }
         printf("client_leave performed\n");
         return;
	
}

void client_new_sess(client* c, message m){
    
    int c_id = find_client_index(&m);
    int s_id = create_session(m.data);
    printf("newly created session id is %d\n", s_id);
    if(s_id == -1)
        return;
    
    int err = join_session(s_id, c_id);
    printf("joined session %d\n", err);
   
    if(!err){
        message m_ack = new_message(NS_ACK, 5, "server", m.data);
        char sp[2000];
        int len = 0;
        form_message(m_ack, sp, &len);
        if(send(c->sockfd, sp, len, 0) == -1){
                perror("send login_ack");
                return;
        }

    }

    else{

            message m_ack = new_message(NS_NAK, 5, "server", m.data);
            char sp[2000];
            int len = 0;
            form_message(m_ack, sp, &len);
            if(send(c->sockfd, sp, len, 0) == -1){
                    perror("send login_nak");
                    return;
            }

    }
    printf("client_create performed\n");
    return;
        
}


