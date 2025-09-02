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

bool sz__read_value(sz_state *state, int target, void *buf, size_t buf_size) {
    if (state == NULL || buf == NULL) {
        fprintf(stderr, "sz__read_value: invalid input\n");
        return false;
    }

    if (buf_size == 0) {
        printf("sz__read_value: buf_size=0, nothing to read\n");
        return true;
    }

    size_t total_msg_size = SZ_MAC_NONCE_BYTES + buf_size;
    size_t cipher_msg_size = SZ_MAC_BYTES + buf_size;

    ssize_t result;
    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (state->encrypted) {
            unsigned char server_msg[total_msg_size];
            result = recv(target, server_msg, total_msg_size, 0);
            if (result == 0) {
                printf("sz__read_value: Server socket shutdown\n");
                return false;
            } else if (result == -1) {
                fprintf(stderr, "sz__read_value: %s\n", strerror(errno));
                return false;
            } else if ((size_t)result != total_msg_size) {
                fprintf(stderr,
                        "sz__read_value: couldn't recv all bytes from server. "
                        "want: %zu, got: %zu\n",
                        total_msg_size, result);
                return false;
            }

            unsigned char cipher_msg[cipher_msg_size];
            memcpy(cipher_msg, server_msg, cipher_msg_size);

            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, server_msg + cipher_msg_size, crypto_box_NONCEBYTES);

            unsigned char decrypted[buf_size];
            if (crypto_box_open_easy(decrypted, cipher_msg, cipher_msg_size,
                                     nonce, state->server_public_key,
                                     state->secret_key) != 0) {
                fprintf(
                    stderr,
                    "sz__read_value: Failed to decrypt message from server\n");
                return false;
            }
            memcpy(buf, decrypted, buf_size);
        } else {
            result = recv(target, buf, buf_size, 0);
            if (result == 0) {
                printf("sz__read_value: Server socket shutdown\n");
                return false;
            } else if (result == -1) {
                fprintf(stderr, "sz__read_value: %s\n", strerror(errno));
                return false;
            } else if ((size_t)result != buf_size) {
                fprintf(stderr,
                        "sz__read_value: couldn't recv all bytes from server. "
                        "want: %zu, got: %zu\n",
                        buf_size, result);
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
                    "sz__read_value: invalid input, client not found\n");
            return false;
        }
        sz_client client = state->clients[target];

        if (client.encrypted) {
            unsigned char client_msg[total_msg_size];
            result = recv(client.fd, client_msg, total_msg_size, 0);
            if (result == 0) {
                printf("sz__read_value: Client socket shutdown\n");
                return false;
            } else if (result == -1) {
                fprintf(stderr, "sz__read_value: %s\n", strerror(errno));
                return false;
            } else if ((size_t)result != total_msg_size) {
                fprintf(stderr,
                        "sz__read_value: couldn't recv all bytes from client. "
                        "want: %zu, got: %zu\n",
                        total_msg_size, result);
                return false;
            }

            unsigned char cipher_msg[cipher_msg_size];
            memcpy(cipher_msg, client_msg, cipher_msg_size);

            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, client_msg + cipher_msg_size, crypto_box_NONCEBYTES);

            unsigned char decrypted[buf_size];
            if (crypto_box_open_easy(decrypted, cipher_msg, cipher_msg_size,
                                     nonce, client.public_key,
                                     state->secret_key) != 0) {
                fprintf(
                    stderr,
                    "sz__read_value: Failed to decrypt message from client\n");
                return false;
            }
            memcpy(buf, decrypted, buf_size);
        } else {
            result = recv(client.fd, buf, buf_size, 0);
            if (result == 0) {
                printf("sz__read_value: Client socket shutdown\n");
                return false;
            } else if (result == -1) {
                fprintf(
                    stderr,
                    "sz__read_value: Failed to recv message from client: %s\n",
                    strerror(errno));
                return false;
            } else if ((size_t)result != buf_size) {
                fprintf(stderr,
                        "sz__read_value: couldn't recv all bytes from client. "
                        "want: %zu, got: %zu\n",
                        buf_size, result);
                return false;
            }
        }
    } break;
    }

    return true;
}

bool sz__send_value(sz_state *state, int target, void *content,
                    size_t content_size) {
    if (state == NULL || content == NULL) {
        fprintf(stderr, "sz__send_value: invalid input\n");
        return false;
    }

    size_t total_msg_size = SZ_MAC_NONCE_BYTES + content_size;
    size_t cipher_msg_size = SZ_MAC_BYTES + content_size;

    int fd;
    void *buf;
    size_t buf_size;
    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        fd = target;

        if (state->encrypted) {
            unsigned char nonce[crypto_box_NONCEBYTES];
            unsigned char cipher_text[cipher_msg_size];
            // sent_content: "cipher_text"+"nonce"
            unsigned char sent_content[total_msg_size];

            randombytes_buf(nonce, sizeof(nonce));
            if (crypto_box_easy(cipher_text, content, content_size, nonce,
                                state->server_public_key,
                                state->secret_key) != 0) {
                fprintf(stderr, "sz__send_value: Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_content, cipher_text, cipher_msg_size);
            memcpy(sent_content + cipher_msg_size, nonce,
                   crypto_box_NONCEBYTES);

            buf = sent_content;
            buf_size = total_msg_size;
        } else {
            buf = content;
            buf_size = content_size;
        }
    } break;
    case SZ_STATE_TYPE_SERVER: {
        // its relatively safe to cast int to size_t
        // because negative values of 'target' are
        // being checked before
        if (target < 0 || (size_t)target >= state->clients_size) {
            fprintf(stderr,
                    "sz__send_value: invalid input, client not found\n");
            return false;
        }
        sz_client client = state->clients[target];
        fd = client.fd;

        if (client.encrypted) {
            unsigned char nonce[crypto_box_NONCEBYTES];
            unsigned char cipher_text[cipher_msg_size];
            // sent_content: "cipher_text"+"nonce"
            unsigned char sent_content[total_msg_size];

            randombytes_buf(nonce, sizeof(nonce));
            if (crypto_box_easy(cipher_text, content, content_size, nonce,
                                client.public_key, state->secret_key) != 0) {
                fprintf(stderr, "sz__send_value: Failed to encrypt message\n");
                return false;
            }

            memcpy(sent_content, cipher_text, cipher_msg_size);
            memcpy(sent_content + cipher_msg_size, nonce,
                   crypto_box_NONCEBYTES);

            buf = sent_content;
            buf_size = total_msg_size;
        } else {
            buf = content;
            buf_size = content_size;
        }
    } break;
    default: {
        fprintf(stderr, "sz__send_value: unknown state type with id '%d'\n",
                state->type);
        return false;
    } break;
    }

    ssize_t result = send(fd, buf, buf_size, 0);
    if (result == -1) {
        fprintf(stderr, "sz__send_value: %s\n", strerror(errno));
        return false;
    } else if ((size_t)result != buf_size) {
        fprintf(stderr,
                "sz__send_value: could not send all bytes. "
                "want: %zu, sent: %zu\n",
                buf_size, result);
        return false;
    }
    return true;
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

bool sz_rm_client(sz_state *state, size_t client_id) {
    if (state == NULL || state->type != SZ_STATE_TYPE_SERVER) {
        fprintf(stderr, "sz_rm_client: invalid input\n");
        return false;
    }

    if (client_id >= state->clients_size) {
        fprintf(stderr, "sz_rm_client: invalid client_id '%zu'\n", client_id);
        return false;
    }

    for (size_t i = client_id + 1; i < state->clients_size; i++) {
        sz_client tmp = state->clients[i - 1];
        state->clients[i - 1] = state->clients[i];
        state->clients[i] = tmp;
    }
    state->clients_size--;
    return true;
}

size_t sz_push_client(sz_state *state, int fd, struct sockaddr_in addr) {
    if (state == NULL || state->type != SZ_STATE_TYPE_SERVER || fd == -1) {
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

bool sz_read_command(sz_state *state, int target, sz_command *cmd) {
    if (state == NULL || cmd == NULL) {
        fprintf(stderr, "sz_read_command: invalid input\n");
        return false;
    }

    size_t id_size = sizeof(cmd->id);
    char buf[SZ_TEXT_SIZE + id_size];
    if (!sz__read_value(state, target, buf, SZ_TEXT_SIZE + id_size)) {
        return false;
    }

    cmd->id = buf[0];
    memcpy(cmd->message, buf + id_size, SZ_TEXT_SIZE);
    return true;
}

bool sz_send_command(sz_state *state, int target, sz_command cmd) {
    if (state == NULL) {
        fprintf(stderr, "sz_send_command: invalid input\n");
        return false;
    }

    size_t id_size = sizeof(cmd.id);
    char buf[SZ_TEXT_SIZE + id_size];
    buf[0] = cmd.id;
    memcpy(buf + id_size, cmd.message, SZ_TEXT_SIZE);

    if (!sz__send_value(state, target, buf, SZ_TEXT_SIZE + id_size)) {
        return false;
    }
    return true;
}

bool sz_handshake(sz_state *state, int target, unsigned char *public_key) {
    if (state == NULL) {
        fprintf(stderr, "sz_handshake: invalid input");
        return false;
    }

    sz_command cmd;
    switch (state->type) {
    case SZ_STATE_TYPE_CLIENT: {
        cmd = (sz_command){.id = SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE};
        memcpy(cmd.message, state->public_key, crypto_box_PUBLICKEYBYTES);
        if (!sz_send_command(state, target, cmd))
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

        cmd = (sz_command){.id = SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE};
        memcpy(cmd.message, state->public_key, crypto_box_PUBLICKEYBYTES);
        if (!sz_send_command(state, target, cmd))
            return false;

        client->encrypted = true;
    } break;
    }
    return true;
}
