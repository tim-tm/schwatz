#define _POSIX_C_SOUCRE 200809L
#define _GNU_SOURCE

#include "sz.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <isocline.h>
#include <pthread.h>

#define USAGE_STR "Usage: schwatz [client|server] <hostname> [port]"

void *client_read_server(void *ptr);
void *server_handle_client(void *ptr);

static sz_state *state;

static pthread_t read_thread;
static int read_thread_return = -1;

int main(int argc, char **argv) {
    (void)(argc);

    const char *program_name = *argv++;
    if (program_name == NULL) {
        fprintf(stderr,
                "Unexpected error, program_name is NULL!\n" USAGE_STR "\n");
        return 1;
    }

    const char *subcommand = *argv++;
    if (subcommand == NULL) {
        fprintf(stderr, "Please specify a subcommand!\n" USAGE_STR "\n");
        return 1;
    }

    enum sz_state_type type = SZ_STATE_TYPE_CLIENT;
    if (strncmp("client", subcommand, 6) == 0) {
        type = SZ_STATE_TYPE_CLIENT;
    } else if (strncmp("server", subcommand, 6) == 0) {
        type = SZ_STATE_TYPE_SERVER;
    } else {
        fprintf(stderr, "Unknown subcommand '%s'\n" USAGE_STR "\n", subcommand);
        return 1;
    }

    const char *hostname = *argv++;
    if (hostname == NULL) {
        fprintf(stderr, "Please specify a hostname!\n" USAGE_STR "\n");
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid hostname! (%s)\n" USAGE_STR "\n", hostname);
        return 1;
    }

    const char *port_str = *argv++;
    int port = 9999;
    if (port_str != NULL) {
        char *end;
        port = strtol(port_str, &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "Invalid port '%s': %s!\n" USAGE_STR "\n", port_str,
                    strerror(errno));
            return 1;
        }
    }
    addr.sin_port = htons(port);

    state = sz_init(type);
    if (state == NULL) {
        fprintf(stderr, "Failed to initialize state!\n");
        return 1;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return 1;
    }

    switch (type) {
    case SZ_STATE_TYPE_CLIENT: {
        if (connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            fprintf(stderr, "Failed to connect to server: %s\n",
                    strerror(errno));
            return 1;
        }

        // will be free'd inside of the thread
        int *p_socket_fd = (int *)malloc(sizeof(int));
        if (p_socket_fd == NULL) {
            fprintf(stderr, "Failed to allocate memory for p_socket_fd!\n");
            return 1;
        }
        *p_socket_fd = socket_fd;
        pthread_create(&read_thread, NULL, client_read_server, p_socket_fd);

        sz_handshake(state, socket_fd, NULL);
        while (!state->encrypted) {
        }

        ic_set_history(NULL, -1);

        char *input;
        char msg[SZ_TEXT_SIZE];
        while ((input = ic_readline("schwatz")) != NULL) {
            size_t input_len = strnlen(input, SZ_TEXT_SIZE - 2);
            strncpy(msg, input, input_len);

            // needed to flush the pending message
            msg[input_len] = '\n';
            msg[input_len + 1] = '\0';

            if (read_thread_return != -1)
                return 1;

            if (strstr(msg, "/cmd") != NULL) {
                fprintf(stderr, "Failed to send message: Message should not "
                                "contain '/cmd'\n");
                continue;
            }

            sz_command cmd = {.id = SZ_CLIENT_COMMAND_MESSAGE};
            memcpy(cmd.message, msg, SZ_TEXT_SIZE);
            if (!sz_send_command(state, socket_fd, cmd)) {
                return 1;
            }

            ic_history_add(input);
            free(input);
        }
        pthread_detach(read_thread);
    } break;
    case SZ_STATE_TYPE_SERVER: {
        if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            fprintf(stderr, "Could not bind socket: %s\n", strerror(errno));
            close(socket_fd);
            return 1;
        }

        if (listen(socket_fd, 32) == -1) {
            fprintf(stderr, "Could not listen on socket: %s\n",
                    strerror(errno));
            close(socket_fd);
            return 1;
        }

        char *s = inet_ntoa(addr.sin_addr);
        printf("Running schwatz-server on %s:%i!\n", s, port);

        struct sockaddr_in client_addr;
        size_t client_addr_size = sizeof(struct sockaddr_in);
        while (1) {
            int client_fd = accept(socket_fd, (struct sockaddr *)&client_addr,
                                   (socklen_t *)&client_addr_size);
            if (client_fd == -1) {
                fprintf(stderr, "Could not accept client: %s\n",
                        strerror(errno));
                continue;
            }

            size_t client_id = sz_push_client(state, client_fd, client_addr);
            if (client_id == SIZE_MAX) {
                fprintf(stderr, "Could not accept client: internal error\n");
                return 1;
            }

            pthread_t t;
            // will be free'd inside of the thread
            size_t *p_client_id = (size_t *)malloc(sizeof(size_t));
            if (p_client_id == NULL) {
                fprintf(stderr, "Failed to allocate memory for p_client_id!\n");
                return 1;
            }
            *p_client_id = client_id;
            pthread_create(&t, NULL, server_handle_client, p_client_id);
        }
    } break;
    }

    close(socket_fd);
    sz_destroy(state);
    return 0;
}

void *client_read_server(void *ptr) {
    int socket_fd = *((int *)ptr);
    free(ptr);

    while (1) {
        sz_command *cmd = calloc(1, sizeof(sz_command));
        if (cmd == NULL) {
            fprintf(stderr, "Failed to allocate memory for server_msg!\n");
            read_thread_return = 1;
            return NULL;
        }

        if (!sz_read_command(state, socket_fd, cmd)) {
            read_thread_return = 1;
            return NULL;
        }

        switch (cmd->id) {
        case SZ_SERVER_COMMAND_ERROR: {
            fprintf(stderr, "Server error: %s\n", cmd->message);
            free(cmd);
            read_thread_return = 1;
            return NULL;
        } break;
        case SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE: {
            fprintf(stderr, "server_public_key:\n %s\n",
                    sz__hex_str((unsigned char *)cmd->message,
                                crypto_box_PUBLICKEYBYTES));
            memcpy(state->server_public_key, cmd->message,
                   crypto_box_PUBLICKEYBYTES);
            state->encrypted = true;
        } break;
        case SZ_SERVER_COMMAND_MESSAGE: {
            printf("%s", cmd->message);
        } break;
        default: {
            fprintf(stderr,
                    "Invalid server command! (%d)\nThe server could run on "
                    "a different version!\n",
                    cmd->id);
            free(cmd);
            read_thread_return = 1;
            return NULL;
        } break;
        }
        free(cmd);
    }
    read_thread_return = 0;
    return NULL;
}

void *server_handle_client(void *ptr) {
    size_t client_id = *((size_t *)ptr);
    free(ptr);
    sz_client client = state->clients[client_id];

    sz_command *cmd = malloc(sizeof(sz_command));
    if (cmd == NULL) {
        fprintf(stderr, "Could not create buffer for message\n");
        close(client.fd);
        return NULL;
    }

    int failed = 0;
    while (sz_read_command(state, client_id, cmd) && !failed) {
        char *s = inet_ntoa(client.addr.sin_addr);

        switch (cmd->id) {
        case SZ_CLIENT_COMMAND_ERROR: {
            fprintf(stderr, "Client error: %s\n", cmd->message);
            failed = 1;
        } break;
        case SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE: {
            if (!sz_handshake(state, client_id,
                              (unsigned char *)cmd->message)) {
                sz_command cmd = {.id = SZ_SERVER_COMMAND_ERROR,
                                  .message = "Failed to generate keys!"};
                sz_send_command(state, client_id, cmd);
                failed = 1;
            }
        } break;
        case SZ_CLIENT_COMMAND_MESSAGE: {
            printf("%s: %s", s, (char *)cmd);
            for (size_t i = 0; i < state->clients_size; i++) {
                if (i != client_id) {
                    char *temp = calloc(SZ_TEXT_SIZE, sizeof(char));
                    if (temp == NULL) {
                        fprintf(stderr,
                                "Could not create buffer for message\n");
                        continue;
                    }
                    snprintf(temp, SZ_TEXT_SIZE, "%s: %s", s, (char *)cmd);

                    sz_command cmd = {.id = SZ_SERVER_COMMAND_MESSAGE};
                    memcpy(cmd.message, temp, SZ_TEXT_SIZE);
                    sz_send_command(state, i, cmd);
                    free(temp);
                }
            }
        } break;
        default: {
            fprintf(stderr,
                    "Invalid client command! (%d)\nThe client could run on "
                    "a different version!\n",
                    cmd->id);
            failed = 1;
        } break;
        }
    }
    close(client.fd);
    free(cmd);
    sz_rm_client(state, client_id);
    return NULL;
}
