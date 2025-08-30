#include <arpa/inet.h>
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#define SZ_MESSAGE_SIZE 256
#define SZ_SERVER_ENCRYPTED_MESSAGE_SIZE                                       \
    (crypto_box_MACBYTES + crypto_box_NONCEBYTES + SZ_MESSAGE_SIZE)
#define SZ_SERVER_CIPHER_MESSAGE_SIZE (crypto_box_MACBYTES + SZ_MESSAGE_SIZE)
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

sz_state *sz_init(enum sz_state_type type);
void sz_destroy(sz_state *state);

size_t sz_push_client(sz_state *state, int fd, struct sockaddr_in addr);
bool sz_read_message(sz_state *state, int target, void *buffer);
bool sz_send_message(sz_state *state, int target, const char *msg);
bool sz_send_command(sz_state *state, int target, int cmd, const char *msg);
bool sz_handshake(sz_state *state, int target, unsigned char *public_key);
