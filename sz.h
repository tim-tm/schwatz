#include <arpa/inet.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define SZ_TEXT_SIZE 256
#define SZ_MAC_NONCE_BYTES (crypto_box_MACBYTES + crypto_box_NONCEBYTES)
#define SZ_MAC_BYTES (crypto_box_MACBYTES)

enum sz_client_command {
    SZ_CLIENT_COMMAND_ERROR,
    SZ_CLIENT_COMMAND_ENCRYPTION_HANDSHAKE,
    SZ_CLIENT_COMMAND_MESSAGE,
};

enum sz_server_command {
    SZ_SERVER_COMMAND_ERROR,
    SZ_SERVER_COMMAND_ENCRYPTION_HANDSHAKE,
    SZ_SERVER_COMMAND_MESSAGE,
};

enum sz_state_type {
    SZ_STATE_TYPE_SERVER,
    SZ_STATE_TYPE_CLIENT,
};

typedef struct sz_command {
    char id;
    char message[SZ_TEXT_SIZE];
} sz_command;

typedef struct sz_client {
    int fd;
    struct sockaddr_in addr;
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
bool sz__read_value(sz_state *state, int target, void *buf, size_t buf_name);
bool sz__send_value(sz_state *state, int target, void *content,
                    size_t content_size);

sz_state *sz_init(enum sz_state_type type);
void sz_destroy(sz_state *state);

bool sz_rm_client(sz_state *state, size_t client_id);
size_t sz_push_client(sz_state *state, int fd, struct sockaddr_in addr);
bool sz_read_command(sz_state *state, int target, sz_command *cmd);
bool sz_send_command(sz_state *state, int target, sz_command cmd);
bool sz_handshake(sz_state *state, int target, unsigned char *public_key);
