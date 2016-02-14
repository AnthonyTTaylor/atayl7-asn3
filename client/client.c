#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <unistd.h>
#include <zlib.h>
#include "hmdp.h"
#include <err.h>
#include <netdb.h>
#include <sys/param.h>
#include <hfs.h>
#include <errno.h>



#include "../common/udp_client.h"
#include "../common/udp_sockets.h"


int open_connection(struct addrinfo* addr_list)
{
  struct addrinfo* addr;
  int sockfd;
  // Iterate through each addrinfo in the list; stop when we successfully
  // connect to one
  for (addr = addr_list; addr != NULL; addr = addr->ai_next)
  {
    // Open a socket
    sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    // Try the next address if we couldn't open a socket
    if (sockfd == -1)
    continue;
    // Stop iterating if we're able to connect to the server
    if (connect(sockfd, addr->ai_addr, addr->ai_addrlen) != -1)
    break;
  }
  // Free the memory allocated to the addrinfo list
  freeaddrinfo(addr_list);
  // If addr is NULL, we tried every addrinfo and weren't able to connect to any
  if (addr == NULL)
  err(EXIT_FAILURE, "%s", "Unable to connect");
  else
  return sockfd;
}

struct addrinfo* get_sockaddr(const char* hostname, const char* port)
{
  struct addrinfo hints;
  struct addrinfo* results;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET; // Return socket addresses for the server's IPv4 addresses
  hints.ai_socktype = SOCK_STREAM; // Return TCP socket addresses
  int retval = getaddrinfo(NULL, port, &hints, &results);
  if (retval)
  errx(EXIT_FAILURE, "%s", gai_strerror(retval));
  return results;

}

unsigned long fsize(char* file)
{
    FILE * f = fopen(file, "r");
    fseek(f, 0, SEEK_END);
    unsigned long len = (unsigned long)ftell(f);
    fclose(f);
    return len;
}

message* create_control_message(hfs_entry* currentFile, char* authToken, uint8_t type, int sequence)
{

  // Create a 16-byte message
  control_message* msg = (control_message*)create_message();
  // Store the operand count in the first byte of the message

  msg->type = type; //Always 0
  msg->sequence = sequence;

  //msg->filenameLength = *((uint16_t *)currentFile->rel_path);
  msg->filenameLength = strlen(currentFile->rel_path);
  msg->fileSize = fsize(currentFile->abs_path);
  msg->checksum = (currentFile->crc32);
  //msg->token = (uint16_t*)authToken;

  msg->filename = *((uint8_t *)currentFile->abs_path);
  char* padding = "";
  memcpy(msg->token, authToken, 16);
  memcpy(msg->padding, padding, (unsigned)strlen(currentFile->abs_path));

  // printf("%u\n",sizeof(uint32_t) );
  // printf("%u\n",sizeof(msg->type) );
  // printf("%u\n",sizeof(msg->sequence));
  // printf("%u\n", sizeof(msg->filenameLength));
  // printf("%u\n", sizeof(msg->fileSize));
  // printf("%u\n", sizeof(msg->checksum));
  // printf("%u\n", sizeof(msg->token));
  // printf("%u\n", sizeof(msg->padding));

  msg->length = sizeof(uint32_t) + sizeof(msg->type) + sizeof(msg->sequence) + sizeof(msg->filenameLength) + sizeof(msg->fileSize) + (uint32_t)sizeof(msg->checksum) + sizeof(msg->token) + sizeof(msg->padding);
  // Return the dynamically-allocated message
  return (message*)msg;
}

message* create_data_message(hfs_entry* currentFile, uint8_t type, int sequence)
{
  data_message* msg = (data_message*)create_message();
  msg->length = 1500;

  msg->type = type;
  msg->sequence = sequence;
  unsigned long length = fsize(currentFile->abs_path);

  //uint8_t *data = (uint8_t*)malloc(size * sizeof(uint8_t));
  msg->data = length;
  //memcpy(msg->data, data, sizeof(msg->data));
  return (message*)msg;
}

char *hmds_authToken(char *username, char *password, char *serverName, char* serverPort)
{
  struct hmdp_request *msg1 = hmdp_create_auth_request(username, password);
  struct addrinfo* results = get_sockaddr(serverName, serverPort);
  int sockfd2 = open_connection(results);
  int send_request = hmdp_send_request(msg1,sockfd2);
  // Send the message
  if (send_request == -1)
  err(EXIT_FAILURE, "%s", "Unable to send");
  // Read the echo reply

  struct hmdp_response *hmds_response_messsage = hmdp_read_response(sockfd2);
  char *authToken = malloc(16* sizeof(uint8_t));
  strcpy(authToken,hmdp_header_get(hmds_response_messsage->headers, "Token"));
  hmdp_free_response(hmds_response_messsage);
  hmdp_free_request(msg1);
  close(sockfd2);
  return authToken;
}


int main(int argc, char **argv)
{
  int c;
  int i;
  char *serverPort = "9000";
  char *serverName  = "localhost";
  char *directory = "~/Hooli";
  static int verbose_flag = 0;
  char *log_filename = "";
  char *username;
  char *password;
  char *HOSTNAME = "localhost";
  char *PORT = "10000";

  while(1){
    int option_index = 0;
    static struct option long_options[] =
    {
      {"server", optional_argument, 0, 's'},
      {"port", optional_argument, 0, 'p'},
      {"dir", optional_argument, 0, 'd' },
      {"verbose", no_argument, &verbose_flag, 1 },
      {"log", optional_argument, 0, 'l'},
      {"fserver", optional_argument, 0, 'f' },
      {"fport", optional_argument, 0, 'o' },
      {0, 0, 0, 0}
    };
    const char* shortopts = "vl:s:p:d:f:o:";
    c = getopt_long(argc, argv, shortopts, long_options, &option_index);

    // If we've reached the end of the options, stop iterating
    if (c == -1)
    break;
    switch (c)
    {
      case 'l':
      log_filename = optarg;
      break;
      case 's':
      serverName = optarg;
      break;
      case 'p':
      serverPort = optarg;
      break;
      case 'd':
      directory = optarg;
      break;
      case 'v':
      verbose_flag = (int)optarg;
      break;
      case 'f':
      HOSTNAME = optarg;
      break;
      case 'o':
      PORT = optarg;
      break;
      case '?':
      // Error message already printed by getopt_long -- we'll just exit
      exit(EXIT_FAILURE);
      break;
    }
  }

  for (i = optind; i < argc; ++i)
  {
    username = argv[i];
    password = argv[i+1];
    i++;
  }
  printf("Logfile :%s\n",log_filename);
  //hmds_authToken sends a reqest with a username and password to a server and port to get a 16bit Oauth token
  char* authToken = hmds_authToken(username, password, serverName, serverPort);
  printf("%s\n", authToken);
  //syslog(LOG_INFO, "Scanning Directory :%s",directory);

  //This talks to the HMDS to get Files and CheckSums
  errno = 0;
  hfs_entry* files = hfs_get_files(directory);
  hfs_entry* cur = files;

  char *body;
  asprintf(&body,"%s\n%X", cur->rel_path, cur->crc32);
  cur = cur->next;
  while(cur != NULL) {
    char* tmp;
    asprintf(&tmp,"%s\n%s\n%x", body, cur->rel_path, cur->crc32);
    free(body);
    asprintf(&body, "%s", tmp);
    free(tmp);
    cur = cur->next;
  }
  struct hmdp_request* hmdp_file_list = hmdp_create_list_request(authToken, body);
  struct addrinfo* results = get_sockaddr(serverName, serverPort);
  int sockfd2 = open_connection(results);
  int send_request = hmdp_send_request(hmdp_file_list, sockfd2);
  // Send the message
  if (send_request == -1)
  err(EXIT_FAILURE, "%s", "Unable to send");
  // Read the echo reply
  struct hmdp_response* hmds_response_messsage = hmdp_read_response(sockfd2);
  if (hmds_response_messsage->code == 401){
    printf("Error with return message\n");
  }
  char* list_of_files;
  asprintf(&list_of_files,"%s", hmds_response_messsage->body);

  close(sockfd2);
  hmdp_free_response(hmds_response_messsage);
  hmdp_free_request(hmdp_file_list);


  //HFTP Server code
  host server; // Server address
  response_message* response;

  //HFTP Connection
  // Create a socket for communication with the server
  int sockfd = create_client_socket(HOSTNAME, PORT, &server);
  // Create a message, and initialize its contents
  hfs_entry* filesToTransfer = hfs_get_files(directory);
  hfs_entry* currentFile = filesToTransfer;
  while(currentFile != NULL) {
    if (strstr(list_of_files, currentFile->rel_path) != NULL) {
      printf("HFTP Client requests %s\n", (char*)(currentFile->rel_path));
      message *msg = create_control_message(currentFile, authToken, 1, 0);
      send_message(sockfd, msg, &server);
      free(msg);

      //response
      response = (response_message*)receive_message(sockfd, &server);
      if (response->type == 255){
        printf("Reponse:255 - Start Transfer\n");
        message *dataMsg = create_data_message(currentFile, 3, 1);
        send_message(sockfd, dataMsg, &server);
        message *termMsg = create_control_message(currentFile,authToken,2,0);
        send_message(sockfd, termMsg, &server);
        free(dataMsg);
        free(termMsg);
      }
      // printf("Result: %u\n", ((response_message*)response)->type);
    }
    //asprintf(&tmp,"%s\n%s\n%x", body, cur->rel_path, cur->crc32);
    currentFile = currentFile->next;
  }



  // message *msg = create_control_message(currentFile, authToken);
  // send_message(sockfd, msg, &server);
  // free(msg);
  //
  // response = (response_message*)receive_message(sockfd, &server);

  // Print the result and close the socket
  //printf("Result: %u\n", ((response_message*)response)->type);
  //cur = cur->next;


  close(sockfd);
  exit(EXIT_SUCCESS);

}
