#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <hdb.h>
#include "../common/udp_sockets.h"
#include "../common/udp_server.h"



#define BACKLOG 25
// Note: make sure there are *no* spaces after the backslash below
#define SOCK_TYPE(s) (s == SOCK_STREAM ? "Stream" : s == SOCK_DGRAM ? "Datagram" : s == SOCK_RAW ? "Raw" : "Other")

void handle_connection(int connectionfd)
{
  char buffer[4096];
  int bytes_read;
  do
  {
    // Read up to 4095 bytes from the client
    bytes_read = recv(connectionfd, buffer, sizeof(buffer)-1, 0);
    // If the data was read successfully
    if (bytes_read > 0)
    {
      // Add a terminating NULL character and print the message received
      buffer[bytes_read] = '\0';
      printf("Message received (%d bytes): %s\n", bytes_read, buffer);
      // Echo the data back to the client; exit loop if we're unable to send
      if (send(connectionfd, buffer, bytes_read, 0) == -1)
      {
        warn("Unable to send data to client");
        break;
      }
    }
  } while (bytes_read > 0);
  // Close the connection
  close(connectionfd);
}

message* create_response_message(control_message* result)
{

  // Create a response message and initialize it
  response_message* response = (response_message*)create_message();
  response->length = 1500;
  response->type = 255;
  response->sequence = result->sequence;
  response->errorCode = 0;

  // Return the dynamically-allocated message
  return (message*)response;


}

int wait_for_connection(int sockfd)
{
  struct sockaddr_in client_addr;      // Remote IP that is connecting to us
  unsigned int addr_len = sizeof(struct sockaddr_in); // Length of the remote IP structure
  char ip_address[INET_ADDRSTRLEN];    // Buffer to store human-friendly IP address
  int connectionfd;                    // Socket file descriptor for the new connection
  // Wait for a new connection
  connectionfd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);
  // Make sure the connection was established successfully
  if (connectionfd == -1)
  err(EXIT_FAILURE, "%s", "Unable to accept connection");
  // Convert the connecting IP to a human-friendly form and print it
  inet_ntop(client_addr.sin_family, &client_addr.sin_addr, ip_address, sizeof(ip_address));
  printf("Connection accepted from %s\n", ip_address);
  // Return the socket file descriptor for the new connection
  return connectionfd;
}

int main(int argc, char **argv)
{
  int c;
  char *serverPort = "10000";
  char *serverName  = "localhost";
  char *directory = "/tmp/hftpd";
  int waittime = 10;
  //printf("%s\n",serverName );
  static int verbose_flag = 0;
  //char *log_filename = NULL;

  while(1){
    int option_index = 0;
    static struct option long_options[] =
    {
      {"reddis", optional_argument, 0, 'r'},
      {"port", optional_argument, 0, 'p'},
      {"verbose", no_argument, &verbose_flag, 1 },
      {"waittime", no_argument, 0, 't'},
      {"ROOT", no_argument, 0, 'd'},
      {0, 0, 0, 0}
    };
    const char* shortopts = "vr:p:w:d:";
    c = getopt_long(argc, argv, shortopts, long_options, &option_index);

    // If we've reached the end of the options, stop iterating
    if (c == -1)
    break;
    switch (c)
    {
      case 'r':
      serverName = optarg;
      break;
      case 'p':
      serverPort = optarg;
      break;
      case 'v':
      verbose_flag = 1;
      break;
      case 'w':
      waittime = (int)optarg;
      break;
      case 'd':
      directory = optarg;
      break;
      case '?':
      // Error message already printed by getopt_long -- we'll just exit
      exit(EXIT_FAILURE);
      break;
    }
  }

  printf("WaitTime:%i Directory:%s Servername:%s \n",waittime, directory, serverName );
  printf("FTP Server listening on port %s\n", serverPort );
  control_message* request; // Client's request message
  message* response; // Server response message
  host client; // Client's address

   hdb_connection* con = hdb_connect("localhost");
   if(con == NULL){
     printf("Not Connected\n");
   }else printf("Connected to Redis\n");
  // char* username = hdb_verify_token(con, "KTLw3ClK7WohIx1C");

  //
  // char* authToken = hdb_authenticate(con, "username", "password");
  // Close the socket
  // Create a socket to listen on port 9000
  int sockfd = create_server_socket(serverPort);
  while(1){
    // Read the request message and generate the response
    request = (control_message*)receive_message(sockfd, &client);
    if (request->type == 1) {
      printf("Messaged Recived for First\n");
      response = create_response_message(request);
      free(response);
      /* code */
    }else if (request->type == 3) {
      printf("Messaged Recived for Data\n");
      response = create_response_message(request);

      // uint8_t buffer = (uint8_t*)request->data;
      // FILE *fp;
      // fp = fopen("filename.txt", "wb");
      // fwrite(buffer, sizeof(char), sizeof(buffer), fp);
      // fclose(fp);
      free(response);

    }

    //response = create_response_message(request);
    // Send the response and free the memory allocated to the messages
    send_message(sockfd, response, &client);
    free(request);


  }

  close(sockfd);
  exit(EXIT_SUCCESS);
}
