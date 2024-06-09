#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define SERVER_MESSAGE_SIZE 512
#define NICKNAME_SIZE 64

typedef struct _Client_ {
    int fd;
    struct sockaddr_in addr;
    char nickname[NICKNAME_SIZE];

    struct _Client_ *next;
    struct _Client_ *prev;
} Client;

static Client *server_clients_last;
static Client *server_clients_first;

void *handle_client(void *ptr);

int main(int argc, char **argv) {
    int port = 9999;
    if (argc >= 2) {
        char *end;
        int r = strtol(argv[1], &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "Usage: %s <port>\n", argv[0]);
            return 1;
        }
        port = r;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        fprintf(stderr, "Could not create socket: %s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {0},
        .sin_zero = {0}
    };

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 32) == -1) {
        fprintf(stderr, "Could not listen on socket: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    char *s = inet_ntoa(addr.sin_addr);
    printf("Running schwatz-server on %s:%i!\n", s, port);

    struct sockaddr_in client_addr;
    size_t client_addr_size = sizeof(struct sockaddr_in);
    while (1) {
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, (socklen_t*)&client_addr_size);
        if (client_fd == -1) {
            fprintf(stderr, "Could not accept client: %s\n", strerror(errno));
            continue;
        }
        
        Client *p_client_fd = malloc(sizeof(Client));
        p_client_fd->fd = client_fd;
        p_client_fd->addr = client_addr;
        strncpy(p_client_fd->nickname, inet_ntoa(client_addr.sin_addr), NICKNAME_SIZE);

        if (server_clients_last == NULL) {
            p_client_fd->next = NULL;
            p_client_fd->prev = NULL;
            server_clients_last = p_client_fd;
            server_clients_first = p_client_fd;
        } else {
            p_client_fd->prev = server_clients_last;
            p_client_fd->next = NULL;
            server_clients_last->next = p_client_fd;
            server_clients_last = p_client_fd;
        }

        pthread_t t;
        pthread_create(&t, NULL, handle_client, p_client_fd);
    }
    close(server_fd);
    Client *cl = server_clients_first;
    while (cl != NULL) {
        Client *next = cl->next;
        free(cl);
        cl = next;
    }
    return 0;
}

void *handle_client(void *ptr) {
    Client *client = (Client*)ptr;
    
    char buf[SERVER_MESSAGE_SIZE] = { 0 }; /* recv buffer */
    char temp[SERVER_MESSAGE_SIZE * 2] = { 0 }; /* message that will be sent to all the clients */
    
    while (recv(client->fd, buf, SERVER_MESSAGE_SIZE, 0) > 0) {
        char *s = client->nickname;
        printf("%s: %s", s, buf);
        
        /* check for command */
        if (buf[0] == '/') {
        	char *p = buf;
        	while (*p != ' ' && *p != '\n' && *p != '\0') p++;
        	*p = '\0';
        	if (!strcmp(buf + 1, "nick")) {
        		/* set the new nickname */
        		p++;
        		if (*p == '\0') {
        			/* there is no nickname: do nothing */
        			/* should maybe report that to the client */
        			send(client->fd, "Error: invalid nickname.\n", 26, 0);
        			printf("Error: invalid nickname.\n");
        			continue;
        		} else {
				char *q = p;
				while (*q != '\n' && *q != '\0') q++;
				*q = '\0';
        			char old_nickname[NICKNAME_SIZE];
        			strncpy(old_nickname, client->nickname, NICKNAME_SIZE);
        			strncpy(client->nickname, p, NICKNAME_SIZE);
        			snprintf(temp, SERVER_MESSAGE_SIZE*2, "%s is now known as %s.\n", old_nickname, p);
        		}
        	}
        } else {
        	snprintf(temp, SERVER_MESSAGE_SIZE*2, "%s: %s", s, buf);
        }
        
        /* send the message to each client */
	Client *current = server_clients_first;
	while (current != NULL) {
		if (current != client) {
			send(current->fd, temp, SERVER_MESSAGE_SIZE*2, 0);
		}
		current = current->next;
	}
        memset(buf, 0, SERVER_MESSAGE_SIZE);
        memset(temp, 0, SERVER_MESSAGE_SIZE*2);
    }
    close(client->fd);

    if (client->next != NULL) {
        client->next->prev = client->prev;
    } else if (client->prev != NULL) {
        client->prev->next = NULL;
    } else {
        server_clients_last = NULL;
        server_clients_first = NULL;
    }
    free(client);
    return NULL;
}
