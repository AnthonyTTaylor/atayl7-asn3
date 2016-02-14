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
#include <unistd.h> // for close
#include <fcntl.h>
#include <hdb.h>


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


struct addrinfo* get_server_sockaddr(const char* address, const char* port)
{
  struct addrinfo hints;
  struct addrinfo* results;
  struct addrinfo* res; // Pointer to a result in the linked list
  char ip_address[INET_ADDRSTRLEN]; // Buffer to store human-readable IP address

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET; // Return socket addresses for our local IPv4 addresses
  hints.ai_socktype = SOCK_STREAM; // Return TCP socket addresses
  hints.ai_flags = AI_PASSIVE; // Socket addresses should be for listening sockets
  int retval = getaddrinfo(address, port, &hints, &results);
  if (retval)
  errx(EXIT_FAILURE, "%s", gai_strerror(retval));
  for (res = results; res != NULL; res = res->ai_next)
  {
    //     HERE IS WHERE I WOULD DO SOMETHING WITH THE RETRUNED IP ADDRRESSES

    // Cast the result's address to a Internet socket address
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    // Convert it from its packed, binary form to a human readable string
    inet_ntop(res->ai_family, &ipv4->sin_addr, ip_address, sizeof(ip_address));
    // Display the IP address, socket type, and protocol
    printf("%-15s %-10s %s\n", ip_address, SOCK_TYPE(res->ai_socktype),
    getprotobynumber(res->ai_protocol)->p_name);
  }
  // Free the memory allocated to the linked list
  //freeaddrinfo(results);
  return results;
}

int bind_socket(struct addrinfo* addr_list)
{
  struct addrinfo* addr;
  int sockfd;
  // Iterate over the addresses in the list; stop when we successfully bind to one
  for (addr = addr_list; addr != NULL; addr = addr->ai_next)
  {
    // Open a socket
    sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    // Move on to the next address if we couldn't open a socket
    if (sockfd == -1)
    continue;
    // Try to bind the socket to the address/port
    if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) == -1)
    {
      // If binding fails, close the socket, and move on to the next address
      close(sockfd);
      continue;
    }
    else
    {
      // Otherwise, we've bound the address to the socket, so stop processing
      break;
    }
  }
  // Free the memory allocated to the address list
  freeaddrinfo(addr_list);
  // If addr is NULL, we tried every address and weren't able to bind to any
  if (addr == NULL)
  {
    err(EXIT_FAILURE, "%s", "Unable to bind");
  }
  else
  {
    // Otherwise, return the socket descriptor
    return sockfd;
  }
}


int wait_for_connection(int sockfd)
{
  struct sockaddr_in client_addr; // Remote IP that is connecting to us
  unsigned int addr_len = sizeof(struct sockaddr_in); // Length of the remote IP structure
  char ip_address[INET_ADDRSTRLEN]; // Buffer to store human-friendly IP address
  int connectionfd; // Socket file descriptor for the new connection
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
  char *serverPort = "9000";
  char *serverName  = "localhost";
  printf("%s\n",serverName );
  static int verbose_flag = 0;
  //char *log_filename = NULL;

  while(1){
    int option_index = 0;
    static struct option long_options[] =
    {
      {"server", optional_argument, 0, 's'},
      {"port", optional_argument, 0, 'p'},
      {"verbose", no_argument, &verbose_flag, 1 },
      {0, 0, 0, 0}
    };
    const char* shortopts = "vs:p:";
    c = getopt_long(argc, argv, shortopts, long_options, &option_index);

    // If we've reached the end of the options, stop iterating
    if (c == -1)
    break;
    switch (c)
    {
      case 's':
      serverName = optarg;
      break;
      case 'p':
      serverPort = optarg;
      break;
      case 'v':
      verbose_flag = 1;
      break;
      case '?':
      // Error message already printed by getopt_long -- we'll just exit
      exit(EXIT_FAILURE);
      break;
    }
  }


  // We want to listen on the port specified on the command line
  struct addrinfo* results = get_server_sockaddr(serverName, serverPort);
  // Create a listening socket
  int sockfd = bind_socket(results);
  // Start listening on the socket
  if (listen(sockfd, BACKLOG) == -1)
  err(EXIT_FAILURE, "%s", "Unable to listen on socket");
while(1)
{
  // Wait for a connection
  int connectionfd = wait_for_connection(sockfd);
  handle_connection(connectionfd);
}
  // Close the connection socket
  //close(connectionfd);

  // Close the greeter socket and exit
  close(sockfd);
  exit(EXIT_SUCCESS);
  //return 0;
}
