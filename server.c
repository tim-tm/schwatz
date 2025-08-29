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

#define MESSAGE_SIZE 512
#define SERVER_ENCRYPTED_MESSAGE_SIZE (crypto_box_MACBYTES+crypto_box_NONCEBYTES+MESSAGE_SIZE*2)
#define SERVER_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES+MESSAGE_SIZE*2)
#define CLIENT_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES+MESSAGE_SIZE)
#define CLIENT_ENCRYPTED_MESSAGE_SIZE (crypto_box_MACBYTES+crypto_box_NONCEBYTES+MESSAGE_SIZE)

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

bool read_message(Client *client, void *buf);
void print_hex(unsigned char *data, size_t data_len);
bool send_message(Client *client, const char *msg);
bool send_command(Client *client, enum ServerCommand cmd,  const char *msg);
bool client_gen_keys(Client *client, unsigned char *client_public_key);
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

    if (sodium_init() != 0) {
        fprintf(stderr, "Could not initialize encyption (sodium_init)\n");
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
        p_client_fd->encrypted = false;

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

bool read_message(Client *client, void *buf) {
    if (client == NULL || buf == NULL) return false;
    if (client->encrypted) {
        unsigned char client_msg[CLIENT_ENCRYPTED_MESSAGE_SIZE];
        if (read(client->fd, client_msg, CLIENT_ENCRYPTED_MESSAGE_SIZE) == -1) {
            fprintf(stderr, "Failed to read message from client: %s\n", strerror(errno));
            return false;
        }

        unsigned char cipher_msg[CLIENT_CIPHER_MESSAGE_SIZE];
        memcpy(cipher_msg, client_msg, CLIENT_CIPHER_MESSAGE_SIZE);

        unsigned char nonce[crypto_box_NONCEBYTES];
        memcpy(nonce, client_msg+CLIENT_CIPHER_MESSAGE_SIZE, crypto_box_NONCEBYTES);

        unsigned char decrypted[MESSAGE_SIZE];
        if (crypto_box_open_easy(decrypted,
                    cipher_msg,
                    CLIENT_CIPHER_MESSAGE_SIZE,
                    nonce,
                    client->client_public_key,
                    client->secret_key) != 0) {
            fprintf(stderr, "Failed to decrypt message from client\n");
            return false;
        }
        memcpy(buf, decrypted, MESSAGE_SIZE);
    } else {
        if (recv(client->fd, buf, MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to recv message from client: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

void print_hex(unsigned char *data, size_t data_len) {
    for (size_t i = 0; i < data_len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

bool send_message(Client *client, const char *msg) {
    if (client == NULL || client->fd == -1 || msg == NULL) return false;
    
    if (client->encrypted) {
        unsigned char nonce[crypto_box_NONCEBYTES];
        unsigned char cipher_text[SERVER_CIPHER_MESSAGE_SIZE];
        // sent_msg: "cipher_text"+"nonce"
        unsigned char sent_msg[SERVER_ENCRYPTED_MESSAGE_SIZE];

        unsigned char uc_msg[MESSAGE_SIZE*2];
        memcpy(uc_msg, msg, MESSAGE_SIZE*2);
        randombytes_buf(nonce, sizeof(nonce));
        if (crypto_box_easy(cipher_text, uc_msg, MESSAGE_SIZE*2, nonce, client->client_public_key, client->secret_key) != 0) {
            fprintf(stderr, "Failed to encrypt message\n");
            return false;
        }
        
        memcpy(sent_msg, cipher_text, SERVER_CIPHER_MESSAGE_SIZE);
        memcpy(sent_msg+SERVER_CIPHER_MESSAGE_SIZE, nonce, crypto_box_NONCEBYTES);

        if (send(client->fd, sent_msg, SERVER_ENCRYPTED_MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            return false;
        }
    } else {
        if (send(client->fd, msg, MESSAGE_SIZE*2, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            return false;
        }
    }
    return true;
}

bool send_command(Client *client, enum ServerCommand cmd,  const char *msg) {
    if (client == NULL || msg == NULL) return false;
    char *sent_msg = calloc(MESSAGE_SIZE*2, sizeof(char));
    if (sent_msg == NULL) {
        fprintf(stderr, "Failed to allocate memory for message!\n");
        return false;
    }
    snprintf(sent_msg, MESSAGE_SIZE*2, "/cmd %d %s", cmd, msg);
    if (!send_message(client, sent_msg)) {
        fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
        free(sent_msg);
        return false;
    }
    free(sent_msg);
    return true;
}

void *handle_client(void *ptr) {
    Client *client = (Client*)ptr;

    void *buf = malloc(MESSAGE_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client->fd);
        return NULL;
    }
    
    int failed = 0;
    while (read_message(client, buf) && !failed) {
        char *s = inet_ntoa(client->addr.sin_addr);

        char *cmd_start;
        if ((cmd_start = strstr(buf, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *buf_copy = calloc(MESSAGE_SIZE, sizeof(char));
            if (buf_copy == NULL) {
                fprintf(stderr, "Failed to allocate memory for buf_copy!\n");
                failed = 1;
            }
            strncpy(buf_copy, buf, MESSAGE_SIZE);

            // extract the id
            // commands[0] = "/cmd"
            // commands[1] = "<id>"
            void *commands[3] = {0};
            char *split = strtok(cmd_start, " ");
            for (size_t i = 0; i < 2 && split != NULL; ++i) {
                commands[i] = split;
                split = strtok(NULL, " ");
            }

            if (split != NULL) {
                // extract the full message
                // commands[2] = "<message>"
                void *msg_start = strstr(buf_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum ServerCommand command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr, "Invalid client command! (%s)\nThe client could run on a different version!\n", (char*)commands[1]);
                free(buf_copy);
                failed = 1;
                continue;
            }

            switch (command) {
                case CLIENT_COMMAND_ERROR: {
                    fprintf(stderr, "Client error: %s\n", (char*)commands[2]);
                    failed = 1;
                } break;
                case CLIENT_COMMAND_ENCRYPTION_HANDSHAKE: {
                    if (!client_gen_keys(client, (unsigned char*)commands[2])) {
                        send_command(client, SERVER_COMMAND_ERROR, "Failed to generate keys!");
                        failed = 1;
                    }
                } break;
                default: {
                    fprintf(stderr, "Invalid client command! (%s)\nThe client could run on a different version!\n", (char*)commands[1]);
                    failed = 1;
                } break;
            }
            free(buf_copy);
            memset(buf, 0, MESSAGE_SIZE);
            continue;
        }

        printf("%s: %s", s, (char*)buf);
        Client *current = server_clients_first;
        while (current != NULL) {
            if (current != client) {
                char *temp = calloc(MESSAGE_SIZE*2, sizeof(char));
                if (temp == NULL) {
                    fprintf(stderr, "Could not create buffer for message\n");
                    continue;
                }
                snprintf(temp, MESSAGE_SIZE*2, "%s: %s", s, (char*)buf);
                send_message(current, temp);
                free(temp);
            }
            current = current->next;
        }
        memset(buf, 0, MESSAGE_SIZE);
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

bool client_gen_keys(Client *client, unsigned char *client_public_key) {
    if (client == NULL || client_public_key == NULL) return false;

    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
        client->client_public_key[i] = client_public_key[i];
    }
    
    crypto_box_keypair(client->public_key, client->secret_key);
    printf("client_public_key\n");
    print_hex(client->client_public_key, crypto_box_PUBLICKEYBYTES);
    printf("public_key\n");
    print_hex(client->public_key, crypto_box_PUBLICKEYBYTES);
    printf("secret_key\n");
    print_hex(client->secret_key, crypto_box_SECRETKEYBYTES);
    if (!send_command(client, SERVER_COMMAND_ENCRYPTION_HANDSHAKE, (char*)client->public_key)) return false;

    client->encrypted = true;
    return true;
}
