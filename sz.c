#include "sz.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

static char sz__hex_str_result[2048];
const char *sz__hex_str(unsigned char *data, size_t data_len) {
    memset(sz__hex_str_result, 0, 2048);
    for (size_t i = 0; i < data_len; ++i) {
        snprintf(&sz__hex_str_result[i * 2], 2048, "%02x", data[i]);
    }
    return sz__hex_str_result;
}

sz_state *sz_init(enum sz_state_type type) {
    if (sodium_init() != 0) {
        fprintf(stderr, "sz_init: Failed to init sodium!\n");
        return NULL;
    }

    sz_state *state = (sz_state *)calloc(1, sizeof(sz_state));
    if (state == NULL) {
        fprintf(stderr, "sz_init: Could not allocate memory for sz_state\n");
        return NULL;
    }

    state->type = type;
    if (state->type == SZ_STATE_TYPE_SERVER) {
        state->clients_capacity = 32;
        state->clients = calloc(state->clients_capacity, sizeof(sz_client));
    }

    crypto_box_keypair(state->public_key, state->secret_key);
    printf("state.public_key\n %s\n",
           sz__hex_str(state->public_key, crypto_box_PUBLICKEYBYTES));
    printf("state.secret_key\n %s\n",
           sz__hex_str(state->secret_key, crypto_box_SECRETKEYBYTES));
    return state;
}

void sz_destroy(sz_state *state) {
    if (state == NULL)
        return;

    if (state->clients)
        free(state->clients);
    free(state);
}

size_t sz_push_client(sz_state *state, int fd, struct sockaddr_in addr) {
    if (state == NULL || fd == -1) {
        fprintf(stderr, "sz_push_client: invalid input\n");
        return SIZE_MAX;
    }

    if (state->clients_size >= state->clients_capacity) {
        state->clients_capacity *= 2;
        state->clients = realloc(state->clients, state->clients_capacity);
    }
    state->clients[state->clients_size++] = (sz_client){
        .fd = fd,
        .addr = addr,
    };
    return state->clients_size - 1;
}

bool sz_read_message(sz_state *state, int target, void *buffer) {
    if (state == NULL || buffer == NULL) {
        fprintf(stderr, "sz_read_message: invalid input\n");
        return false;
    }

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (state->encrypted) {
            unsigned char server_msg[SZ_SERVER_ENCRYPTED_MESSAGE_SIZE];
            if (read(target, server_msg, SZ_SERVER_ENCRYPTED_MESSAGE_SIZE) ==
                -1) {
                fprintf(stderr, "sz_read_message: %s\n", strerror(errno));
                return false;
            }

            unsigned char cipher_msg[SZ_SERVER_CIPHER_MESSAGE_SIZE];
            memcpy(cipher_msg, server_msg, SZ_SERVER_CIPHER_MESSAGE_SIZE);

            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, server_msg + SZ_SERVER_CIPHER_MESSAGE_SIZE,
                   crypto_box_NONCEBYTES);

            unsigned char decrypted[SZ_MESSAGE_SIZE];
            if (crypto_box_open_easy(
                    decrypted, cipher_msg, SZ_SERVER_CIPHER_MESSAGE_SIZE, nonce,
                    state->server_public_key, state->secret_key) != 0) {
                fprintf(
                    stderr,
                    "sz_read_message: Failed to decrypt message from server\n");
                return false;
            }
            memcpy(buffer, decrypted, SZ_MESSAGE_SIZE);
        } else {
            if (read(target, buffer, SZ_MESSAGE_SIZE) == -1) {
                fprintf(stderr, "sz_read_message: %s\n", strerror(errno));
                return false;
            }
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            fprintf(stderr,
                    "sz_read_message: invalid input, client not found\n");
            return false;
        }
        sz_client client = state->clients[target];

        if (client.encrypted) {
            unsigned char client_msg[SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE];
            if (read(client.fd, client_msg, SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE) ==
                -1) {
                fprintf(stderr, "sz_read_message: %s\n", strerror(errno));
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
                fprintf(
                    stderr,
                    "sz_read_message: Failed to decrypt message from client\n");
                return false;
            }
            memcpy(buffer, decrypted, SZ_MESSAGE_SIZE);
        } else {
            if (recv(client.fd, buffer, SZ_MESSAGE_SIZE, 0) == -1) {
                fprintf(
                    stderr,
                    "sz_read_message: Failed to recv message from client: %s\n",
                    strerror(errno));
                return false;
            }
        }
    } break;
    }

    return true;
}

bool sz_send_message(sz_state *state, int target, const char *msg) {
    if (state == NULL || msg == NULL) {
        fprintf(stderr, "sz_send_message: invalid input\n");
        return false;
    }

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
                fprintf(stderr, "sz_send_message: Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_msg, cipher_text, SZ_CLIENT_CIPHER_MESSAGE_SIZE);
            memcpy(sent_msg + SZ_CLIENT_CIPHER_MESSAGE_SIZE, nonce,
                   crypto_box_NONCEBYTES);

            if (send(target, sent_msg, SZ_CLIENT_ENCRYPTED_MESSAGE_SIZE, 0) ==
                -1) {
                fprintf(stderr, "sz_send_message: %s\n", strerror(errno));
                return false;
            }
        } else {
            if (send(target, msg, SZ_MESSAGE_SIZE, 0) == -1) {
                fprintf(stderr, "sz_send_message: %s\n", strerror(errno));
                return false;
            }
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            fprintf(stderr,
                    "sz_send_message: invalid input, client not found\n");
            return false;
        }
        sz_client client = state->clients[target];

        if (client.encrypted) {
            unsigned char nonce[crypto_box_NONCEBYTES];
            unsigned char cipher_text[SZ_SERVER_CIPHER_MESSAGE_SIZE];
            // sent_msg: "cipher_text"+"nonce"
            unsigned char sent_msg[SZ_SERVER_ENCRYPTED_MESSAGE_SIZE];

            unsigned char uc_msg[SZ_MESSAGE_SIZE];
            memcpy(uc_msg, msg, SZ_MESSAGE_SIZE);
            randombytes_buf(nonce, sizeof(nonce));
            if (crypto_box_easy(cipher_text, uc_msg, SZ_MESSAGE_SIZE, nonce,
                                client.public_key, state->secret_key) != 0) {
                fprintf(stderr, "sz_send_message: Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_msg, cipher_text, SZ_SERVER_CIPHER_MESSAGE_SIZE);
            memcpy(sent_msg + SZ_SERVER_CIPHER_MESSAGE_SIZE, nonce,
                   crypto_box_NONCEBYTES);

            if (send(client.fd, sent_msg, SZ_SERVER_ENCRYPTED_MESSAGE_SIZE,
                     0) == -1) {
                fprintf(stderr, "sz_send_message: Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        } else {
            if (send(client.fd, msg, SZ_MESSAGE_SIZE, 0) == -1) {
                fprintf(stderr, "sz_send_message: Failed to send message: %s\n",
                        strerror(errno));
                return false;
            }
        }
    } break;
    }

    return true;
}

bool sz_send_command(sz_state *state, int target, int cmd, const char *msg) {
    if (state == NULL || msg == NULL) {
        fprintf(stderr, "sz_send_command: invalid input\n");
        return false;
    }

    char *sent_msg = calloc(SZ_MESSAGE_SIZE, sizeof(char));
    if (sent_msg == NULL) {
        fprintf(stderr,
                "sz_send_command: Failed to allocate memory for message!\n");
        return false;
    }

    snprintf(sent_msg, SZ_MESSAGE_SIZE, "/cmd %d %s", cmd, msg);

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (!sz_send_message(state, target, sent_msg)) {
            free(sent_msg);
            return false;
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            fprintf(stderr,
                    "sz_send_command: invalid input, client not found\n");
            free(sent_msg);
            return false;
        }

        if (!sz_send_message(state, target, sent_msg)) {
            free(sent_msg);
            return false;
        }
    } break;
    }

    free(sent_msg);
    return true;
}

bool sz_handshake(sz_state *state, int target, unsigned char *public_key) {
    if (state == NULL) {
        fprintf(stderr, "sz_handshake: invalid input");
        return false;
    }

    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (!sz_send_command(state, target,
                             SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE,
                             (char *)state->public_key))
            return false;
    } break;
    case SZ_STATE_TYPE_SERVER: {
        if (public_key == NULL) {
            fprintf(stderr, "sz_handshake: invalid input, public_key = NULL");
            return false;
        }

        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            fprintf(stderr, "sz_handshake: invalid input, client not found");
            return false;
        }
        // we need to use the pointer to the struct because
        // wouldn't be able to modify it otherwise
        sz_client *client = &state->clients[target];

        memcpy(client->public_key, public_key, crypto_box_PUBLICKEYBYTES);
        printf("client.public_key\n %s\n",
               sz__hex_str(client->public_key, crypto_box_PUBLICKEYBYTES));

        if (!sz_send_command(state, target,
                             SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE,
                             (char *)state->public_key))
            return false;

        client->encrypted = true;
    } break;
    }
    return true;
}
