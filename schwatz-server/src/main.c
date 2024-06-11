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
#include <sodium.h>

/**
 * TODO: Send and receive encrypted messages encrypted with the exchanged keys
 */

#define SERVER_MESSAGE_SIZE 512

enum ClientCommand {
    CLIENT_COMMAND_ERROR = -1,
    CLIENT_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

enum ServerCommand {
    SERVER_COMMAND_ERROR = -1,
    SERVER_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

typedef struct _Client_ {
    int fd;
    struct sockaddr_in addr;
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];
    unsigned char client_public_key[crypto_box_PUBLICKEYBYTES];
    bool encrypted;

    struct _Client_ *next;
    struct _Client_ *prev;
} Client;

static Client *server_clients_last;
static Client *server_clients_first;

bool send_command(Client *client, enum ServerCommand cmd,  const char *msg);
bool client_gen_keys(Client *client, char *client_public_key);
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

bool send_command(Client *client, enum ServerCommand cmd,  const char *msg) {
    if (client == NULL || msg == NULL) return false;
    char sent_msg[SERVER_MESSAGE_SIZE*2];
    snprintf(sent_msg, SERVER_MESSAGE_SIZE*2, "/cmd %d %s", cmd, msg);
    if (send(client->fd, sent_msg, SERVER_MESSAGE_SIZE*2, 0) == -1) {
        fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
        return false;
    }
    return true;
}

void *handle_client(void *ptr) {
    Client *client = (Client*)ptr;

    char *buf = calloc(SERVER_MESSAGE_SIZE, sizeof(char));
    if (buf == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client->fd);
        return NULL;
    }
    
    int failed = 0;
    while (recv(client->fd, buf, SERVER_MESSAGE_SIZE, 0) > 0 && !failed) {
        char *s = inet_ntoa(client->addr.sin_addr);

        char *cmd_start;
        if ((cmd_start = strstr(buf, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *buf_copy = calloc(SERVER_MESSAGE_SIZE, sizeof(char));
            if (buf_copy == NULL) {
                fprintf(stderr, "Failed to allocate memory for buf_copy!\n");
                failed = 1;
            }
            strncpy(buf_copy, buf, SERVER_MESSAGE_SIZE);

            // extract the id
            // commands[0] = "/cmd"
            // commands[1] = "<id>"
            char *commands[3] = {0};
            char *split = strtok(cmd_start, " ");
            for (size_t i = 0; i < 2 && split != NULL; ++i) {
                commands[i] = split;
                split = strtok(NULL, " ");
            }

            if (split != NULL) {
                // extract the full message
                // commands[2] = "<message>"
                char *msg_start = strstr(buf_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum ServerCommand command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr, "Invalid client command! (%s)\nThe client could run on a different version!\n", commands[1]);
                free(buf_copy);
                failed = 1;
                continue;
            }

            switch (command) {
                case CLIENT_COMMAND_ERROR: {
                    fprintf(stderr, "Client error: %s\n", commands[2]);
                    failed = 1;
                } break;
                case CLIENT_COMMAND_ENCRYPTION_HANDSHAKE: {
                    if (!client_gen_keys(client, commands[2])) {
                        send_command(client, SERVER_COMMAND_ERROR, "Failed to generate keys!");
                        memset(buf, 0, SERVER_MESSAGE_SIZE);
                        free(buf_copy);
                        failed = 1;
                        continue;
                    }
                    client->encrypted = true;
                } break;
                default: {
                    fprintf(stderr, "Invalid client command! (%s)\nThe client could run on a different version!\n", commands[1]);
                    failed = 1;
                } break;
            }
            free(buf_copy);
            memset(buf, 0, SERVER_MESSAGE_SIZE);
            continue;
        }

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

bool client_gen_keys(Client *client, char *client_public_key) {
    if (client == NULL || client_public_key == NULL) return false;

    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
        client->client_public_key[i] = client_public_key[i];
    }
    
    crypto_box_keypair(client->public_key, client->secret_key);
    if (!send_command(client, SERVER_COMMAND_ENCRYPTION_HANDSHAKE, (char*)client->public_key)) return false;    
    return true;
}
