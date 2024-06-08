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

typedef struct _Client_ {
    int fd;
    struct sockaddr_in addr;

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

    char *buf = calloc(SERVER_MESSAGE_SIZE, sizeof(char));
    if (buf == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client->fd);
        return NULL;
    }
    
    while (recv(client->fd, buf, SERVER_MESSAGE_SIZE, 0) > 0) {
        char *s = inet_ntoa(client->addr.sin_addr);
        printf("%s: %s", s, buf);
        Client *current = server_clients_first;
        while (current != NULL) {
            if (current != client) {
                char *temp = calloc(SERVER_MESSAGE_SIZE*2, sizeof(char));
                if (temp == NULL) {
                    fprintf(stderr, "Could not create buffer for message\n");
                    continue;
                }
                snprintf(temp, SERVER_MESSAGE_SIZE*2, "%s: %s", s, buf);
                send(current->fd, temp, SERVER_MESSAGE_SIZE*2, 0);
                free(temp);
            }
            current = current->next;
        }
        memset(buf, 0, SERVER_MESSAGE_SIZE);
    }
    close(client->fd);

    free(buf);
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
