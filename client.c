#include <arpa/inet.h>
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sodium.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MESSAGE_SIZE 512
#define SERVER_ENCRYPTED_MESSAGE_SIZE                                          \
    (crypto_box_MACBYTES + crypto_box_NONCEBYTES + MESSAGE_SIZE * 2)
#define SERVER_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES + MESSAGE_SIZE * 2)
#define CLIENT_ENCRYPTED_MESSAGE_SIZE                                          \
    (crypto_box_MACBYTES + crypto_box_NONCEBYTES + MESSAGE_SIZE)
#define CLIENT_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES + MESSAGE_SIZE)

enum ClientCommand {
    CLIENT_COMMAND_ERROR = -1,
    CLIENT_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

enum ServerCommand {
    SERVER_COMMAND_ERROR = -1,
    SERVER_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

static pthread_t read_thread;
static int read_thread_return = -1;
static unsigned char public_key[crypto_box_PUBLICKEYBYTES];
static unsigned char secret_key[crypto_box_SECRETKEYBYTES];
static unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];
static bool encrypted = false;

bool send_message(int socket_fd, const char *msg);
void print_hex(unsigned char *data, size_t data_len);
bool read_message(int socket_fd, void *msg);
bool send_command(int socket_fd, enum ClientCommand cmd, const char *msg);
bool handle_encryption(int socket_fd);
void *read_server(void *ptr);

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &addr.sin_addr) != 0) {
        fprintf(stderr, "Invalid hostname! (%s)\nUsage: %s <hostname> <port>\n",
                argv[1], argv[0]);
        return 1;
    }

    char *end;
    int port = strtol(argv[2], &end, 10);
    if (*end != '\0') {
        fprintf(stderr, "Invalid port! (%s)\nUsage: %s <hostname> <port>\n",
                argv[2], argv[0]);
        return 1;
    }
    addr.sin_port = htons(port);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        fprintf(stderr, "Failed to connect to server: %s\n", strerror(errno));
        return 1;
    }

    // will be free'd inside of the thread
    int *p_socket_fd = malloc(sizeof(int));
    if (p_socket_fd == NULL) {
        fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
        return 1;
    }
    *p_socket_fd = socket_fd;
    pthread_create(&read_thread, NULL, read_server, p_socket_fd);

    if (!handle_encryption(socket_fd)) {
        return 1;
    }

    char input[MESSAGE_SIZE];
    while (fgets(input, MESSAGE_SIZE, stdin) != NULL) {
        if (read_thread_return != -1)
            return 1;

        if (strstr(input, "/cmd") != NULL) {
            fprintf(stderr, "Failed to send message: Message should not "
                            "contain \"/cmd\"\n");
            memset(input, 0, MESSAGE_SIZE);
            continue;
        }

        if (!send_message(socket_fd, input)) {
            return 1;
        }
        memset(input, 0, MESSAGE_SIZE);
    }

    pthread_detach(read_thread);
    close(socket_fd);
    return 0;
}

bool send_message(int socket_fd, const char *msg) {
    if (socket_fd == -1 || msg == NULL)
        return false;

    if (encrypted) {
        unsigned char nonce[crypto_box_NONCEBYTES];
        unsigned char cipher_text[CLIENT_CIPHER_MESSAGE_SIZE];
        // sent_msg: "cipher_text"+"nonce"
        unsigned char sent_msg[CLIENT_ENCRYPTED_MESSAGE_SIZE];

        unsigned char uc_msg[MESSAGE_SIZE];
        memcpy(uc_msg, msg, MESSAGE_SIZE);
        randombytes_buf(nonce, sizeof(nonce));
        if (crypto_box_easy(cipher_text, uc_msg, MESSAGE_SIZE, nonce,
                            server_public_key, secret_key) != 0) {
            fprintf(stderr, "Failed to encrypt message\n");
            return false;
        }

        memcpy(sent_msg, cipher_text, CLIENT_CIPHER_MESSAGE_SIZE);
        memcpy(sent_msg + CLIENT_CIPHER_MESSAGE_SIZE, nonce,
               crypto_box_NONCEBYTES);

        if (send(socket_fd, sent_msg, CLIENT_ENCRYPTED_MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            return false;
        }
    } else {
        if (send(socket_fd, msg, MESSAGE_SIZE, 0) == -1) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
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

bool read_message(int socket_fd, void *msg) {
    if (socket_fd == -1 || msg == NULL)
        return false;
    if (encrypted) {
        unsigned char server_msg[SERVER_ENCRYPTED_MESSAGE_SIZE];
        if (read(socket_fd, server_msg, SERVER_ENCRYPTED_MESSAGE_SIZE) == -1) {
            fprintf(stderr, "Failed to read message from server: %s\n",
                    strerror(errno));
            return false;
        }

        unsigned char cipher_msg[SERVER_CIPHER_MESSAGE_SIZE];
        memcpy(cipher_msg, server_msg, SERVER_CIPHER_MESSAGE_SIZE);

        unsigned char nonce[crypto_box_NONCEBYTES];
        memcpy(nonce, server_msg + SERVER_CIPHER_MESSAGE_SIZE,
               crypto_box_NONCEBYTES);

        unsigned char decrypted[MESSAGE_SIZE * 2];
        if (crypto_box_open_easy(decrypted, cipher_msg,
                                 SERVER_CIPHER_MESSAGE_SIZE, nonce,
                                 server_public_key, secret_key) != 0) {
            fprintf(stderr, "Failed to decrypt message from server\n");
            return false;
        }
        memcpy(msg, decrypted, MESSAGE_SIZE * 2);
    } else {
        if (read(socket_fd, msg, MESSAGE_SIZE * 2) == -1) {
            fprintf(stderr, "Failed to read message from server: %s\n",
                    strerror(errno));
            return false;
        }
    }
    return true;
}

bool send_command(int socket_fd, enum ClientCommand cmd, const char *msg) {
    if (socket_fd == -1 || msg == NULL)
        return false;

    char sent_msg[MESSAGE_SIZE] = {0};
    snprintf(sent_msg, MESSAGE_SIZE, "/cmd %d %s", cmd, msg);

    if (!send_message(socket_fd, sent_msg)) {
        return false;
    }
    return true;
}

void *read_server(void *ptr) {
    int socket_fd = *((int *)ptr);
    free(ptr);

    while (1) {
        void *server_msg = calloc(MESSAGE_SIZE * 2, sizeof(char));
        if (server_msg == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            read_thread_return = 1;
            return NULL;
        }

        if (!read_message(socket_fd, server_msg)) {
            read_thread_return = 1;
            return NULL;
        }

        char *cmd_start;
        if ((cmd_start = strstr(server_msg, "/cmd")) != NULL) {
            // a command is structured like this: "/cmd <id> <message>"
            // This code splits the string by " " to store the id and message
            char *server_msg_copy = calloc(MESSAGE_SIZE * 2, sizeof(char));
            if (server_msg_copy == NULL) {
                fprintf(stderr,
                        "Failed to allocate memory for server_msg_copy!\n");
                read_thread_return = 1;
                return NULL;
            }
            strncpy(server_msg_copy, server_msg, MESSAGE_SIZE * 2);

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
                void *msg_start = strstr(server_msg_copy, split);
                if (msg_start != NULL) {
                    commands[2] = msg_start;
                }
            }

            // turn the id into an integer value
            // use an enum to properly switch on the value
            char *end;
            enum ServerCommand command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr,
                        "Invalid server command! (%s)\nThe server could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            }

            switch (command) {
            case SERVER_COMMAND_ERROR: {
                fprintf(stderr, "Server error: %s\n", (char *)commands[2]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            } break;
            case SERVER_COMMAND_ENCRYPTION_HANDSHAKE: {
                if (commands[2] != NULL) {
                    for (size_t i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {
                        server_public_key[i] =
                            ((unsigned char *)commands[2])[i];
                    }
                    printf("server_public_key\n");
                    print_hex(server_public_key, crypto_box_PUBLICKEYBYTES);
                    encrypted = true;
                }
            } break;
            default: {
                fprintf(stderr,
                        "Invalid server command! (%s)\nThe server could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                free(server_msg_copy);
                free(server_msg);
                read_thread_return = 1;
                return NULL;
            } break;
            }
            free(server_msg_copy);
            free(server_msg);
            continue;
        }
        printf("%s", (char *)server_msg);
        free(server_msg);
    }
    read_thread_return = 0;
    return NULL;
}

bool handle_encryption(int socket_fd) {
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to start encryption: invalid socket!\n");
        return false;
    }

    if (sodium_init() != 0) {
        fprintf(stderr, "Failed to init sodium!\n");
        return false;
    }

    crypto_box_keypair(public_key, secret_key);
    printf("public_key\n");
    print_hex(public_key, crypto_box_PUBLICKEYBYTES);
    printf("secret_key\n");
    print_hex(secret_key, crypto_box_SECRETKEYBYTES);
    if (!send_command(socket_fd, CLIENT_COMMAND_ENCRYPTION_HANDSHAKE,
                      (char *)public_key))
        return false;

    // wait for the read thread to set the server_public_key
    while (!encrypted) {
    }

    return true;
}
