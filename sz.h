#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define SZ_MESSAGE_SIZE 512
#define SZ_SERVER_ENCRYPTED_MESSAGE_SIZE                                       \
    (crypto_box_MACBYTES + crypto_box_NONCEBYTES + SZ_MESSAGE_SIZE * 2)
#define SZ_SERVER_CIPHER_MESSAGE_SIZE                                          \
    (crypto_box_MACBYTES + SZ_MESSAGE_SIZE * 2)
#define SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE                                       \
    (crypto_box_MACBYTES + crypto_box_NONCEBYTES + SZ_MESSAGE_SIZE)
#define SZ_CLIENT_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES + SZ_MESSAGE_SIZE)

enum sz_client_command {
    SZ_CLIENT_COMMAND_ERROR = -1,
    SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

enum sz_server_command {
    SZ_SERVER_COMMAND_ERROR = -1,
    SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE = 1
};

enum sz_state_type {
    SZ_STATE_TYPE_SERVER,
    SZ_STATE_TYPE_CLIENT,
};

typedef struct sz_client {
    int fd;
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    bool encrypted;
} sz_client;

typedef struct sz_state {
    enum sz_state_type type;
    // either for the client or the server,
    // depending on sz_state_type
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char secret_key[crypto_box_SECRETKEYBYTES];

    // --- client variables ---
    bool encrypted;
    unsigned char server_public_key[crypto_box_PUBLICKEYBYTES];

    // --- server variables ---
    sz_client *clients;
    size_t clients_capacity;
    size_t clients_size;
} sz_state;

const char *sz__hex_str(unsigned char *data, size_t data_len);

sz_state *sz_init(enum sz_state_type type);
void sz_destroy(sz_state *state);

bool sz_push_client(sz_state *state);
bool sz_read_message(sz_state *state, int target, void *buffer);
bool sz_send_message(sz_state *state, int target, const char *msg);
bool sz_send_command(sz_state *state, int target, int cmd, const char *msg);
bool sz_handshake(sz_state *state, int target, unsigned char *public_key);

// #ifdef SZ_IMPLEMENTATION

#include <errno.h>
#include <string.h>
#include <unistd.h>

static char sz__hex_str_result[4096];

const char *sz__hex_str(unsigned char *data, size_t data_len) {
    for (size_t i = 0; i < data_len; ++i) {
        snprintf(sz__hex_str_result, 4096, "%02x", data[i]);
    }
    return sz__hex_str_result;
}

sz_state *sz_init(enum sz_state_type type) {
    if (sodium_init() != 0) {
        fprintf(stderr, "Failed to init sodium!\n");
        return NULL;
    }

    sz_state *state = (sz_state *)calloc(1, sizeof(sz_state));
    if (state == NULL)
        return NULL;

    state->type = type;
    if (state->type == SZ_STATE_TYPE_SERVER) {
        state->clients_capacity = 32;
        state->clients =
            (sz_client *)calloc(state->clients_capacity, sizeof(sz_client));
    }
    return state;
}

void sz_destroy(sz_state *state) {
    if (state == NULL)
        return;
    if (state->clients)
        free(state->clients);
    free(state);
}

bool sz_push_client(sz_state *state) { return true; }

bool sz_read_message(sz_state *state, int target, void *buffer) {
    if (state == NULL || buffer == NULL)
        return false;

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (state->encrypted) {
            unsigned char server_msg[SZ_SERVER_ENCRYPTED_MESSAGE_SIZE];
            if (read(target, server_msg, SZ_SERVER_ENCRYPTED_MESSAGE_SIZE) ==
                -1) {
                fprintf(stderr, "Failed to read message from server: %s\n",
                        strerror(errno));
                return false;
            }

            unsigned char cipher_msg[SZ_SERVER_CIPHER_MESSAGE_SIZE];
            memcpy(cipher_msg, server_msg, SZ_SERVER_CIPHER_MESSAGE_SIZE);

            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, server_msg + SZ_SERVER_CIPHER_MESSAGE_SIZE,
                   crypto_box_NONCEBYTES);

            unsigned char decrypted[SZ_MESSAGE_SIZE * 2];
            if (crypto_box_open_easy(
                    decrypted, cipher_msg, SZ_SERVER_CIPHER_MESSAGE_SIZE, nonce,
                    state->server_public_key, state->secret_key) != 0) {
                fprintf(stderr, "Failed to decrypt message from server\n");
                return false;
            }
            memcpy(buffer, decrypted, SZ_MESSAGE_SIZE * 2);
        } else {
            if (read(target, buffer, SZ_MESSAGE_SIZE * 2) == -1) {
                fprintf(stderr, "Failed to read message from server: %s\n",
                        strerror(errno));
                return false;
            }
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            return false;
        }
        sz_client client = state->clients[target];

        if (client.encrypted) {
            unsigned char client_msg[SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE];
            if (read(client.fd, client_msg, SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE) ==
                -1) {
                fprintf(stderr, "Failed to read message from client: %s\n",
                        strerror(errno));
                return false;
            }

            unsigned char cipher_msg[SZ_CLIENT_CIPHER_MESSAGE_SIZE];
            memcpy(cipher_msg, client_msg, SZ_CLIENT_CIPHER_MESSAGE_SIZE);

            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, client_msg + SZ_CLIENT_CIPHER_MESSAGE_SIZE,
                   crypto_box_NONCEBYTES);

            unsigned char decrypted[SZ_MESSAGE_SIZE];
            if (crypto_box_open_easy(
                    decrypted, cipher_msg, SZ_CLIENT_CIPHER_MESSAGE_SIZE, nonce,
                    client.public_key, state->secret_key) != 0) {
                fprintf(stderr, "Failed to decrypt message from client\n");
                return false;
            }
            memcpy(buffer, decrypted, SZ_MESSAGE_SIZE);
        } else {
            if (recv(client.fd, buffer, SZ_MESSAGE_SIZE, 0) == -1) {
                fprintf(stderr, "Failed to recv message from client: %s\n",
                        strerror(errno));
                return false;
            }
        }
    } break;
    }

    return true;
}

bool sz_send_message(sz_state *state, int target, const char *msg) {
    if (state == NULL || msg == NULL)
        return false;

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (state->encrypted) {
            unsigned char nonce[crypto_box_NONCEBYTES];
            unsigned char cipher_text[SZ_CLIENT_CIPHER_MESSAGE_SIZE];
            // sent_msg: "cipher_text"+"nonce"
            unsigned char sent_msg[SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE];

            unsigned char uc_msg[SZ_MESSAGE_SIZE];
            memcpy(uc_msg, msg, SZ_MESSAGE_SIZE);
            randombytes_buf(nonce, sizeof(nonce));
            if (crypto_box_easy(cipher_text, uc_msg, SZ_MESSAGE_SIZE, nonce,
                                state->server_public_key,
                                state->secret_key) != 0) {
                fprintf(stderr, "Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_msg, cipher_text, SZ_CLIENT_CIPHER_MESSAGE_SIZE);
            memcpy(sent_msg + SZ_CLIENT_CIPHER_MESSAGE_SIZE, nonce,
                   crypto_box_NONCEBYTES);

            if (send(target, sent_msg, SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE, 0) ==
                -1) {
                fprintf(stderr, "Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        } else {
            if (send(target, msg, SZ_MESSAGE_SIZE, 0) == -1) {
                fprintf(stderr, "Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            return false;
        }
        sz_client client = state->clients[target];

        if (client.encrypted) {
            unsigned char nonce[crypto_box_NONCEBYTES];
            unsigned char cipher_text[SZ_SERVER_CIPHER_MESSAGE_SIZE];
            // sent_msg: "cipher_text"+"nonce"
            unsigned char sent_msg[SZ_SERVER_ENCRYPTED_MESSAGE_SIZE];

            unsigned char uc_msg[SZ_MESSAGE_SIZE * 2];
            memcpy(uc_msg, msg, SZ_MESSAGE_SIZE * 2);
            randombytes_buf(nonce, sizeof(nonce));
            if (crypto_box_easy(cipher_text, uc_msg, SZ_MESSAGE_SIZE * 2, nonce,
                                client.public_key, state->secret_key) != 0) {
                fprintf(stderr, "Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_msg, cipher_text, SZ_SERVER_CIPHER_MESSAGE_SIZE);
            memcpy(sent_msg + SZ_SERVER_CIPHER_MESSAGE_SIZE, nonce,
                   crypto_box_NONCEBYTES);

            if (send(client.fd, sent_msg, SZ_SERVER_ENCRYPTED_MESSAGE_SIZE,
                     0) == -1) {
                fprintf(stderr, "Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        } else {
            if (send(client.fd, msg, SZ_MESSAGE_SIZE * 2, 0) == -1) {
                fprintf(stderr, "Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        }
    } break;
    }

    return true;
}

bool sz_send_command(sz_state *state, int target, int cmd, const char *msg) {
    if (state == NULL || msg == NULL)
        return false;

    char *sent_msg = (char *)calloc(SZ_MESSAGE_SIZE, sizeof(char));
    if (sent_msg == NULL) {
        fprintf(stderr, "Failed to allocate memory for message!\n");
        return false;
    }

    snprintf(sent_msg, SZ_MESSAGE_SIZE, "/cmd %d %s", cmd, msg);

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (!sz_send_message(state, target, sent_msg)) {
            return false;
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size)
            return false;

        if (!sz_send_message(state, target, sent_msg)) {
            fprintf(stderr, "Failed to send message: %s\n", strerror(errno));
            free(sent_msg);
            return false;
        }
    } break;
    }

    free(sent_msg);
    return true;
}

bool sz_handshake(sz_state *state, int target, unsigned char *public_key) {
    if (state == NULL)
        return false;

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        crypto_box_keypair(state->public_key, state->secret_key);

        printf("public_key\n  %s\n",
               sz__hex_str(state->public_key, crypto_box_PUBLICKEYBYTES));
        printf("secret_key\n  %s\n",
               sz__hex_str(state->secret_key, crypto_box_SECRETKEYBYTES));

        if (!sz_send_command(state, target,
                             SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE,
                             (char *)state->public_key))
            return false;

        state->encrypted = true;
    } break;
    case SZ_STATE_TYPE_SERVER: {
        if (public_key == NULL)
            return false;

        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            return false;
        }
        sz_client client = state->clients[target];

        memcpy(client.public_key, public_key, crypto_box_PUBLICKEYBYTES);

        crypto_box_keypair(state->public_key, state->secret_key);
        printf("client.public_key\n %s\n",
               sz__hex_str(client.public_key, crypto_box_PUBLICKEYBYTES));
        printf("state.public_key\n %s\n",
               sz__hex_str(state->public_key, crypto_box_PUBLICKEYBYTES));
        printf("state.secret_key\n %s\n",
               sz__hex_str(state->secret_key, crypto_box_SECRETKEYBYTES));

        if (!sz_send_command(state, target,
                             SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE,
                             (char *)state->public_key))
            return false;

        client.encrypted = true;
    } break;
    }
    return true;
}

/*

bool sz_client_handle_encryption(int socket_fd) {
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to start encryption: invalid socket!\n");
        return false;
    }

    if (sodium_init() != 0) {
        fprintf(stderr, "Failed to init sodium!\n");
        return false;
    }

    // wait for the read thread to set the server_public_key
    while (!encrypted) {
    }

    return true;
}

void *sz_server_handle_client(void *ptr) {
    sz_client *client = (sz_client *)ptr;

    void *buf = malloc(MESSAGE_SIZE);
    if (buf == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client->fd);
        return NULL;
    }

    int failed = 0;
    while (sz_server_read_message(client, buf) && !failed) {
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
            enum sz_server_command command = strtol(commands[1], &end, 10);
            if (*end != '\0') {
                fprintf(stderr,
                        "Invalid client command! (%s)\nThe client could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                free(buf_copy);
                failed = 1;
                continue;
            }

            switch (command) {
            case SZ_CLIENT_COMMAND_ERROR: {
                fprintf(stderr, "sz_client error: %s\n", (char *)commands[2]);
                failed = 1;
            } break;
            case SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE: {
                if (!sz_server_gen_client_keys(client,
                                               (unsigned char *)commands[2])) {
                    sz_server_send_command(client, SZ_SERVER_COMMAND_ERROR,
                                           "Failed to generate keys!");
                    failed = 1;
                }
            } break;
            default: {
                fprintf(stderr,
                        "Invalid client command! (%s)\nThe client could run on "
                        "a different version!\n",
                        (char *)commands[1]);
                failed = 1;
            } break;
            }
            free(buf_copy);
            memset(buf, 0, MESSAGE_SIZE);
            continue;
        }

        printf("%s: %s", s, (char *)buf);
        sz_client *current = server_clients_first;
        while (current != NULL) {
            if (current != client) {
                char *temp = calloc(MESSAGE_SIZE * 2, sizeof(char));
                if (temp == NULL) {
                    fprintf(stderr, "Could not create buffer for message\n");
                    continue;
                }
                snprintf(temp, MESSAGE_SIZE * 2, "%s: %s", s, (char *)buf);
                sz_server_send_message(current, temp);
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
*/

// #endif // SZ_IMPLEMENTATION
