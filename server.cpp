//
// Simple chat server for T-409-TSAM
//
// Command line: ./chat_server 4000 
//
// Author: Natalia Potaminaou and Helgi Sævar Thorsteinsson
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <map>
#include <vector>

#include <iostream>
#include <sstream>
#include <chrono>

#include <fstream>
#include <utility> // std::pair
#include <thread>
#include <cctype>
#include <locale>


// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG  5          // Allowed length of queue of waiting connections

std::string OUR_GROUP_ID = "GROUP_96";
std::string OUR_IP;
int OUR_PORT_NUMBER;
int MAX_SERVERS_COUNT = 15;
int BUFFER_SIZE = 1025;
int CLIENT_LISTEN_PORT = 4999;
bool SHOULD_SEND_KEEPALIVE = true;


std::string getTimestamp(){
    time_t now = time(0);
    std::string tmp(ctime(&now));
    tmp.pop_back();
    
    return tmp;
}

// Simple class for handling connections from clients.
// Client(int socket) - socket to send/receive traffic from client.
class Client {
  public:
    int sock;              // socket of client connection
    std::string name;           // Limit length of name of client's user

    Client(int socket) : sock(socket){} 

    ~Client(){}            // Virtual destructor defined for base class
};

// Class to handle messages
class Message {
  public:
    std::string sender_id;
    std::string receiver_id;
    std::string text;
    std::string message_timestamp;

    Message(
      std::string sender,
      std::string receiver,
      std::string messageText) {
        this->sender_id = sender;
        this->receiver_id = receiver;
        this->text = messageText;
        message_timestamp = getTimestamp();
    }
    
    std::string toString() {
        std::string tmp;
        tmp += message_timestamp + ", ";
        tmp += sender_id + ", ";
        tmp += receiver_id + ", ";
        tmp += text;

        return tmp;
    }
    
    ~Message(){}            // Virtual destructor defined for base class
};

class Server {
  public:
    // socket of server connection
    int sock;
    std::string group_id;
    std::string ip_address;
    int port_number;
    std::string connected_time;

    Server(int socket, std::string group_id, std::string ip_address, int port_number) {
        this->sock = socket;
        this->port_number = port_number;
        this->group_id = group_id;
        this->ip_address = ip_address;
        connected_time = getTimestamp();
    }
    
    std::string toString() {
      std::string tmp;
      tmp = group_id + "," + ip_address + "," + std::to_string(port_number) + ";";
      
      return tmp;
    }

    ~Server() {} // Virtual destructor defined for base class
};


std::map<int, Client*> clients; // Lookup table for per Client information
std::map<int, Server*> servers; // Lookup table for per Server information

std::map<std::string, std::vector<Message>> group_messages; //

// Open socket for specified port.
int open_socket(int portno) {
   struct sockaddr_in sk_addr;   // address settings for bind()
   int sock;                     // socket opened for this port
   int set = 1;                  // for setsockopt

   // Create socket for connection. Set to be non-blocking, so recv will
   // return immediately if there isn't anything waiting to be read.
#ifdef __APPLE__     
   if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("Failed to open socket");
      return(-1);
   }
#else
   if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
     perror("Failed to open socket");
    return(-1);
   }
#endif

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.
   if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0) {
      perror("Failed to set SO_REUSEADDR:");
   }
   set = 1;
#ifdef __APPLE__     
   if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0) {
     perror("Failed to set SOCK_NOBBLOCK");
   }
#endif
   memset(&sk_addr, 0, sizeof(sk_addr));

   sk_addr.sin_family      = AF_INET;
   sk_addr.sin_addr.s_addr = INADDR_ANY;
   sk_addr.sin_port        = htons(portno);

   // Bind to socket to listen for connections from clients
   if (bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0){
      perror("Failed to bind to socket:");
      return(-1);
   } else {
      return(sock);
   }
}

void print(std::string text) {
   std::cout << text << std::endl;
}

// Checks if group has messages
bool doesGroupHaveMsg(std::string group_id) {
  // Check if group is in messages
  if (group_messages.find(group_id) == group_messages.end()) {
    return false;
  }
  
  return true;
}



// Returns the servers external IP address of the form 192.168.1.2
// Modified from: https://www.binarytides.com/tcp-syn-portscan-in-c-with-linux-sockets/
std::string getLocalIpAddress() {
  char buffer[1024];
  memset(buffer, 0, sizeof(buffer));

  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  const char *kGoogleDnsIp = "8.8.8.8";
  int dns_port = 53;

  struct sockaddr_in serv;

  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
  serv.sin_port = htons(dns_port);

  connect(sock, (const struct sockaddr *)&serv, sizeof(serv));

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  getsockname(sock, (struct sockaddr *)&name, &namelen);
  close(sock);
  const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);

  std::string address(p);
  return address;
}

int sendClientMessageOverSocket(const int targetSocket, const std::string text) {
  if (send(targetSocket, text.c_str(), text.size(), 0) < 0) {
    std::cout << "Sending '" + text + "' failed" << std::endl;
    return -1;
  }
  return 0;
}

int sendServerMessageOverSocket (const int targetSocket, const std::string command) {
  std::string formattedCommand = "*" + command + "#";
  
  if (send(targetSocket, formattedCommand.c_str(), formattedCommand.size(), 0) < 0) {
    std::cout << "Sending '" + formattedCommand + "' failed" << std::endl;
    return -1;
  }
  return 0;
}


void sleep(int milliseconds) {
  std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

// Send servers number of messages we have in store for them
void sendKeepAliveMessages() {
  SHOULD_SEND_KEEPALIVE = false;
  sleep(60000);
  SHOULD_SEND_KEEPALIVE = true;
  
  for (auto const &pair : servers) {
    Server *server = pair.second;
    
     if (doesGroupHaveMsg(server->group_id)) {
      std::vector<Message> messages = group_messages[server->group_id];
      sendServerMessageOverSocket(server->sock, "KEEPALIVE," + std::to_string(messages.size()));
      return;
    }
  }
  
}

void closeServer(int serverSocket, fd_set *open_sockets, int *maxfds) {
  // Remove client from the servers list
  servers.erase(serverSocket);

  if (*maxfds == serverSocket) {
    for(auto const& p : servers) {
        *maxfds = std::max(*maxfds, p.second->sock);
    }
  }

  // And remove from the list of open sockets.
  FD_CLR(serverSocket, open_sockets);
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.
void closeClient(int clientSocket, fd_set *open_sockets, int *maxfds) {
     // Remove client from the clients list
     clients.erase(clientSocket);

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.
     if (*maxfds == clientSocket) {
        for(auto const& p : clients) {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
     }

     // And remove from the list of open sockets.
     FD_CLR(clientSocket, open_sockets);
}



int connectToServer(std::string ip_address, int port, int *maxfds, fd_set *open_sockets) {
    int socketfd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (socketfd < 0) {
        perror("Failed to open socket");
        exit(0);
    }

    struct sockaddr_in server_socket_addr;                             // address of botnet server
    memset(&server_socket_addr, 0, sizeof(server_socket_addr));        // Initialise memory
    server_socket_addr.sin_family = AF_INET;                           // pv4
    server_socket_addr.sin_addr.s_addr = inet_addr(ip_address.c_str()); // bind to server ip
    server_socket_addr.sin_port = htons(port);                  // portno

    // connect to server
    if (connect(socketfd, (struct sockaddr *)&server_socket_addr, sizeof(server_socket_addr)) < 0) {
        perror("Failed to connect");
        return -1;
    }
    
    printf("Server connected on socket: %d\n", socketfd);
    
    servers[socketfd] = new Server(socketfd, "TBN", ip_address, port);

    // Send the QueryServers command
    sendServerMessageOverSocket(socketfd, "QUERYSERVERS," + OUR_GROUP_ID);

    sleep(600);

    // send_status_request(socketfd);
    *maxfds = std::max(*maxfds, socketfd);
    FD_SET(socketfd, open_sockets);
    return 0;
}


std::string getConnectedServers() {
    std::string tmp = "CONNECTED,";
   
    Server my_server = Server(-1, OUR_GROUP_ID, OUR_IP, OUR_PORT_NUMBER);

    tmp += my_server.toString();

    for (auto const &pair : servers) {
        Server *server = pair.second;
        tmp += server->toString();
    }
    
    return tmp;
}

// trim from both ends
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    
    if (std::string::npos == first) {
        return str;
    }
    
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

void split(std::string &str, std::vector<std::string> &cont, char delim = ' ') {
    std::stringstream ss(str);
    std::string token;
    while (std::getline(ss, token, delim)) {
        cont.push_back(token);
    }
}


void handleServerCommand(
  int serverSocket,
  fd_set *open_sockets,
  int *maxfds, 
  char *buffer){
    
    // TODO: will size of buffer ruin everything here?
    std::string ret(buffer, BUFFER_SIZE);
    
    // Split up the data to get commands
    std::vector<std::string> command_data;
    split(ret, command_data, ',');
    
    // since the last one is big, split it
    std::vector<std::string> command_data_last;
    split(command_data[command_data.size() - 1], command_data_last, '#');
    std::string last_command = command_data_last[0];
  
    if (command_data[0].compare("*QUERYSERVERS") == 0) {
      sendServerMessageOverSocket(serverSocket, getConnectedServers());
      return;
    }
    
    
    
    /* 
      std::cout <<  servers[serverSocket]->ip_address << std::endl;
      std::cout << "CONNECTED response: " << buffer << std::endl;
      
  
      std::cout << "connected_data" << std::endl;
      std::cout << command_data[1] << std::endl;
      std::cout << command_data[2] << std::endl;
      std::cout << command_data[3] << std::endl;
    
    
     */
    
    if (command_data[0].compare("*CONNECTED") == 0) {
      // update since now we get the info
      servers[serverSocket]->group_id = command_data[1];
      return;
    }
    
    if (command_data[0].compare("*STATUSREQ") == 0) {
      if (command_data.size() != 2) {
        sendServerMessageOverSocket(serverSocket, "Usage: *STATUSREQ,<FROM_GROUP>#");
        return;
      }
      
      std::string from_group_id = last_command;
      std::string res = "STATUSRESP," + from_group_id + "," + OUR_GROUP_ID + ",";
      
      // Check what messages we have for servers
      for (auto const &pair : servers) {
        Server *server = pair.second;
        std::cout << server->group_id << std::endl;
        
        if (doesGroupHaveMsg(server->group_id)) {
          std::vector<Message> messages = group_messages[server->group_id];
          std::string noMessages = std::to_string(messages.size());
          res += server->group_id + "," + noMessages + ",";
          return;
        }
      }
      
      sendServerMessageOverSocket(serverSocket, res);
      return;
    }
    
    if (command_data[0].compare("*SEND_MSG") == 0) {
      if (command_data.size() != 4) {
        sendServerMessageOverSocket(serverSocket, "Usage: *SEND_MSG,<TO_GROUP_ID>,<FROM_GROUP_ID>,<MESSAGE_CONTENT>#");
        return;
      }
      
      std::string to_group_id = command_data[1];
      std::string from_group_id = command_data[2];
      std::string message_content = last_command;
      
      // Cut the last character off - #
      group_messages[to_group_id].push_back(Message(from_group_id, to_group_id, message_content));
      std::string res = "Message delivered to: " + to_group_id;
      
      sendServerMessageOverSocket(serverSocket, res);
      return;
    }
    
    if (command_data[0].compare("*GET_MSG") == 0) {
      if (command_data.size() != 2) {
        sendServerMessageOverSocket(serverSocket, "Usage: *GET_MSG,<GROUP_ID>#");
        return;
      }
      
      std::string group_id = last_command;
      
      if (doesGroupHaveMsg(group_id)) {
        std::vector<Message> messages = group_messages[group_id];
        sendServerMessageOverSocket(serverSocket, messages[0].toString());
        return;
      }
      
      sendServerMessageOverSocket(serverSocket, "No messages for group: " + group_id);
      return;
    }
    
    if (command_data[0].compare("*LEAVE") == 0) {
      if (command_data.size() != 3) {
        sendServerMessageOverSocket(serverSocket, "Usage: *LEAVE,<SERVER_IP>,<PORT>#");
        return;
      }
      
      closeServer(serverSocket, open_sockets, maxfds);
      return;
    }
    
    std::cout << "Unknown from server:" << buffer << std::endl;
}



// Process command from client on the server
void handleClientCommand(
  int clientSocket,
  fd_set *open_sockets,
  int *maxfds, 
  char *buffer) {

    std::string ret(buffer, BUFFER_SIZE);
    
    // Split up the data to get commands
    std::vector<std::string> command_data;
    split(ret, command_data, ',');
    
    // since the last one is big due to buffer size, split it
    std::vector<std::string> command_data_last;
    split(command_data[command_data.size() - 1], command_data_last, ' ');
    std::string last_command = command_data_last[0];
    
    if (command_data[0].compare("CONNECTTO") == 0) {
    
      if (command_data.size() != 3) {
        printf("Usage: CONNECTTO,<IP_ADDRESS>,<port> \n");
        return;
      }
      
      std::string ip = command_data[1];
      int port = stoi(command_data[2]);
      
      if (servers.size() > (unsigned)MAX_SERVERS_COUNT) {
        sendClientMessageOverSocket(clientSocket, "Sorry, we cannot connect to more servers");
        return; 
      }
      
      if (connectToServer(ip, port, maxfds, open_sockets) == 0) {
        std::string successMsg = "The server has successfully connected to " + ip + ":" + std::to_string(port);
        
        // Let client know connection was successful
        sendClientMessageOverSocket(clientSocket, successMsg);
        
        return;
      }
      
      if (port == OUR_PORT_NUMBER && ip == OUR_IP) {
        sendClientMessageOverSocket(clientSocket, "We cannot connect to ourselves");
        return;
      }
      
      sendClientMessageOverSocket(clientSocket, "ERROR: Connection attempt failed");
      return;
  }
  
  
  if (command_data[0].compare("GETMSG") == 0) {
    if (command_data.size() != 2) {
      sendClientMessageOverSocket(clientSocket, "Usage: GETMSG,<GROUP_ID>");
      return;
    }
    
    std::string group_id = last_command;
    
    std::cout << group_id.size() << std::endl;
    
    if (doesGroupHaveMsg(group_id)) {
      std::vector<Message> messages = group_messages[group_id];
      sendClientMessageOverSocket(clientSocket, messages[0].toString());
      
      return;
    }
    
    sendClientMessageOverSocket(clientSocket, "No messages for group: " + group_id);
  }
  
  if (command_data[0].compare("SENDMSG") == 0) {
    if (command_data.size() != 2) {
      sendClientMessageOverSocket(clientSocket, "Usage: SENDMSG,<GROUP_ID>");
      return;
    }
    
    std::string target_group_id = last_command;
    group_messages[target_group_id].push_back(Message(OUR_GROUP_ID, target_group_id, "A message from client."));
    
    sendClientMessageOverSocket(clientSocket, "Message delivered to: " + target_group_id);
    return;
  }
  
  std::string LISTSERVERS = "LISTSERVERS";
  
  if (last_command.compare(0, 11, LISTSERVERS) == 0) {
    sendClientMessageOverSocket(clientSocket, getConnectedServers());
    return;
  }
  
  // This prompts our server to send a message to a server on a connected socket.
  // For client to test server-to-server SEND_MSG
  // We have to specify the target server socket
  if (command_data[0].compare("SENDMESSAGETOSERVER") == 0) {
    if (command_data.size() != 4) {
      sendClientMessageOverSocket(clientSocket, "Usage: SENDMESSAGETOSERVER,<CONNECTED_SERVER_SOCKET>,<TO_GROUP_ID>,<MESSAGE>\n");
      return;
    }
    
    int socket = stoi(command_data[1]);
    std::string to_group_id = command_data[2];
    std::string message = command_data[3];
    
    sendServerMessageOverSocket(socket, "SEND_MSG," + to_group_id + "," + OUR_GROUP_ID + "," + message);
    return;
  }
  
  // This prompts our server to get a message from a server on a connected socket.
  // For client to test server-to-server GET_MSG
  // We have to specify the target server socket
  if (command_data[0].compare("GETMESSAGEFROMSERVER") == 0) {
    if (command_data.size() != 3) {
      sendClientMessageOverSocket(clientSocket, "Usage: GETMESSAGEFROMSERVER,<CONNECTED_SERVER_SOCKET>,<GROUP_ID>\n");
      return;
    }
    
    int socket = stoi(command_data[1]);
    std::string group_id = command_data[2];
    
    sendServerMessageOverSocket(socket, "GET_MSG," + group_id);
    return;
  }
  
  if (command_data[0].compare("QUERYSERVER") == 0) {
    if (command_data.size() != 3) {
      sendClientMessageOverSocket(clientSocket, "Usage: QUERYSERVER,<CONNECTED_SERVER_SOCKET>,<GROUP_ID>\n");
      return;
    }
    
    int socket = stoi(command_data[1]);
    std::string group_id = command_data[2];
    
    sendServerMessageOverSocket(socket, "QUERYSERVER," + group_id);
    return;
  }
  
  
/*   if (msg.compare("LEAVE") == 0) {
    // Close the socket, and leave the socket handling
    // code to deal with tidying up clients etc. when
    // select() detects the OS has torn down the connection.

    closeClient(clientSocket, open_sockets, maxfds);
    return;
  } */
  
  std::cout << "Unknown command from client:" << buffer << std::endl;
}


int main(int argc, char* argv[]) {
    int client_listen_sock;            // Socket for connections to clients
    int client_sock;                   // Socket of connecting client
    
    fd_set open_sockets;               // Current open sockets 
    fd_set read_sockets;               // Socket list for select()   
    fd_set except_sockets;             // Exception socket list
    int maxfds;                        // Passed to select() as max fd in set
    
    struct sockaddr_in client;
    socklen_t clientLen;
    char client_buffer[BUFFER_SIZE];   // buffer for reading from clients
         
    int server_listen_sock;            // Socket for connections to server
    int server_sock;                   // Socket of connecting server
    struct sockaddr_in server;
    socklen_t serverLen;
    char server_buffer[BUFFER_SIZE];   // buffer for reading from clients

    if (argc != 2) {
      printf("Usage: ./server <SERVER_LISTEN_PORT>\n");
      exit(0);
    }
    
    OUR_IP = getLocalIpAddress();
    OUR_PORT_NUMBER = atoi(argv[1]);

    // Setup socket for server to listen to
    client_listen_sock = open_socket(CLIENT_LISTEN_PORT); 
    server_listen_sock = open_socket(OUR_PORT_NUMBER); 
    
    printf("Listening for clients on port: %d\n", CLIENT_LISTEN_PORT);
    printf("Listening for servers on port: %d\n", OUR_PORT_NUMBER);
    
    if (listen(client_listen_sock, BACKLOG) < 0) {
      printf("Listen to client failed on port %d\n", CLIENT_LISTEN_PORT);
    }
    
    if (listen(server_listen_sock, BACKLOG) < 0) {
      printf("Listen failed on port %s\n", argv[1]);
      exit(0);
      return 0;
    }
     
    FD_ZERO(&open_sockets);
    FD_SET(client_listen_sock, &open_sockets);
    FD_SET(server_listen_sock, &open_sockets);
    
    maxfds = server_listen_sock;
    
    while (true) {
        // Get modifiable copy of read_sockets
        read_sockets = except_sockets = open_sockets;
        
        memset(client_buffer, 0, sizeof(client_buffer));
        memset(server_buffer, 0, sizeof(server_buffer));

        // Look at sockets and see which ones have something to be read()
        int n_client = select(maxfds + 1, &read_sockets, NULL, &except_sockets, NULL);
        if (n_client < 0) {
            perror("Client select failed - closing down\n");
            break;
        }
        
        int n_server = select(maxfds + 1, &read_sockets, NULL, &except_sockets, NULL);
        
        if (n_server < 0) {
            perror("Server select failed - closing down\n");
            break;
        }
      
        // First, accept any new connections to the client on the listening socket
        if (FD_ISSET(client_listen_sock, &read_sockets)) {
          client_sock = accept(client_listen_sock, (struct sockaddr *)&client, &clientLen);
          // Add new client to the list of open sockets
          FD_SET(client_sock, &open_sockets);

          // And update the maximum file descriptor
          maxfds = std::max(maxfds, client_sock);

          // create a new client to store information.
          clients[client_sock] = new Client(client_sock);

          // Decrement the number of sockets waiting to be dealt with
          n_client--;

          printf("Client connected on socket: %d\n", client_sock);
          sendClientMessageOverSocket(client_sock, "Welcome client.");
          
        } else if (FD_ISSET(server_listen_sock, &read_sockets))  {
          server_sock = accept(server_listen_sock, (struct sockaddr *)&server, &serverLen);
            
          // Add new server to the list of open sockets
          FD_SET(server_sock, &open_sockets);

          // And update the maximum file descriptor
          maxfds = std::max(maxfds, server_sock);
          
          servers[server_sock] = new Server(server_sock, "TBN", "ip_address", server_sock);

          // Decrement the number of sockets waiting to be dealt with
          n_server--;

          printf("Server connected on socket: %d\n", server_sock);
          
          // Send the QueryServers command
          sendServerMessageOverSocket(server_sock, "QUERYSERVERS," + OUR_GROUP_ID);

          sleep(600);
    
          sendServerMessageOverSocket(server_sock, "Welcome Server.");
        }
        
        // Check for commands from clients
        while(n_client-- > 0) {
          for(auto const& pair : clients) {
            Client *client = pair.second;

            if(FD_ISSET(client->sock, &read_sockets)) {
                // recv() == 0 means client has closed connection
                if (recv(client->sock, client_buffer, sizeof(client_buffer), MSG_DONTWAIT) == 0) {
                  printf("Client closed connection: %d", client->sock);
                  close(client->sock);      

                  closeClient(client->sock, &open_sockets, &maxfds);
                  return 0;
                }
                
                // We don't check for -1 (nothing received) because select()
                // only triggers if there is something on the socket for us.
                handleClientCommand(client->sock, &open_sockets, &maxfds, client_buffer);
            }
          }
        }
        
        
        // Check for commands from server
        while(n_server-- > 0) {
          for (auto const &pair : servers) {
            Server *server = pair.second;
            
            if (FD_ISSET(server->sock, &read_sockets)) {
              
              if (recv(server->sock, server_buffer, sizeof(server_buffer), MSG_DONTWAIT) == 0) {
                printf("Server closed connection: %d", server->sock);
                close(server->sock);      
                closeServer(server->sock, &open_sockets, &maxfds);
                return 0;
              }
                
              handleServerCommand(server->sock, &open_sockets, &maxfds, server_buffer);
            }
          }
        }
        if (SHOULD_SEND_KEEPALIVE) {
          sendKeepAliveMessages();
        }
    }
}
