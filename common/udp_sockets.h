#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef UDP_SOCKETS_H
#define UDP_SOCKETS_H

#define UDP_MSS 1472

typedef struct
{
  int length;
  uint8_t buffer[UDP_MSS];
} message;

typedef struct
{
 int length;
 uint8_t type;
 uint8_t sequence;
 uint16_t filenameLength;
 uint32_t fileSize;
 uint32_t checksum;
 uint8_t token[16];
 uint8_t filename;
 uint8_t padding[1444];
} control_message;

// typedef struct {
//    uint32_t length;
//    uint8_t type;               //1 for init, 2 for term
//    uint8_t seq;
//    uint16_t data_len;
//    uint32_t file_size;
//    uint32_t checksum;
//    uint8_t auth_token[AUTH_TOKEN_LEN];
//    uint8_t buffer[MSG_CONTROL_BUFFER_SIZE];
// } msg_control;


typedef struct
{
 int length;
 uint8_t type;
 uint8_t sequence;
 uint16_t dataLength;
 uint8_t data;
 uint8_t padding[1468];
} data_message;

typedef struct
{
 int length;
 uint8_t type;
 uint8_t sequence;
 uint16_t errorCode;
 uint8_t padding;
} response_message;

typedef struct
{
  struct sockaddr_in addr;
  socklen_t addr_len;
  char friendly_ip[INET_ADDRSTRLEN];
} host;

struct addrinfo* get_udp_sockaddr(const char* node, const char* port, int flags);
message* create_message();
message* receive_message(int sockfd, host* source);
int send_message(int sockfd, message* msg, host* dest);

#endif
