#include <stdio.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <unistd.h> 
#include <string> 
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gmpxx.h>
#include <stdexcept>
#include "aes/aes.hpp"
#include "hmac/hmac.h"
#include "ssh.hpp"
#include "RSA/RSA.h"
#include "KeyGen.hpp"

//this is directly copied
int make_client(char * host, char * port) {
  // try to find HOST and PORT
  int client;
  int value;
  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  //set to TCP
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo * res, * itr;
  if ((value = getaddrinfo(host, port, &hints, &res)) != 0) {
    perror("Error: getaddrinfo failed");
    return -1;
  }
  itr = res;
  int sd;
  //loop through every socket and connect to the first one
  while(itr) {
    if ((client = socket(res->ai_family, res->ai_socktype, 0)) == -1) {
	  itr = itr->ai_next;
        continue;
    }
    if (connect(client, res->ai_addr, res->ai_addrlen) == -1) {
        close(client);
	  itr = itr->ai_next;
        continue;
    }
    break;
  }
  freeaddrinfo(res); // all done with this structure
  if (itr == NULL) {
    perror("Error: client failed to connect");
    return -1;
  }
  return client;
}

//this is directly copied
ssize_t try_recv(int cd, char * buf, size_t buflen) {
  assert(buflen < INT_MAX);
  ssize_t len = recv(cd, buf, buflen, MSG_WAITALL);
  if (len == -1) {
    perror("ERROR: Failed to recv message");
    return -1;
  }
  if (len == 0) {
    std::cout << "Server closed connection early." << std::endl;
    return -1;
  }
  if (len < buflen) {
    std::cerr << "Invalid message length" << std::endl;
  std::cerr << "Expected " << buflen << " but received " << len << std::endl;
  return -1;
  }
  return len;
}

//this is original
void hello(int client){
  char buf[256] = {0};
  std::string msg("1234567890");
  //send message
  if (send( client, msg.data(), 10, 0) < 10) {
    std::cerr << "Unable to sned HELLO_LEN len" << std::endl;
    return;
  }
  //recive message
  if (try_recv(client, buf, 10) == -1)
      return;
  std::string received_msg(buf, 10);

  //check if hello passed
  std::cout << "Recived Hello from server: " << received_msg << "\n";
  if (msg.compare(received_msg) == 0){
    printf("Passed hello\n\n" );
  }
}

//send keys, through keys dont actually matter
void keyex(int client, ssh::Keys &all_keys){
  //note I use the programs RSA object, but it is completly default
  //In the client it usually loads some pre-set keys from another file
  //however removing this does not actually effect the cleint at all
  RSA my_rsa;
  //my_rsa.LoadKeys("clientKeys");
  ssh::ClientDiffieKeys diffieKeys(my_rsa);
  if (send(client, diffieKeys.pubKeys(), ssh::CLIENT_KEYEX_LEN, 0) < ssh::CLIENT_KEYEX_LEN) { //sends server pub keys here
    return;
  }
  char hold[ssh::SERVER_KEYEX_LEN] = {0};
  
  //recive server keys
  if (try_recv(client, hold, ssh::SERVER_KEYEX_LEN) == -1)//recives server pub keys here
    return;
  std::cout << "Recived Server Pub Keys: " << hold << "\n";
  if (diffieKeys.genKeys(hold, my_rsa, all_keys) == -1) { //all_keys is set here
    std::cerr << "ERROR: failed to parse diffie keys" << std::endl;
    return;
  }
  std::cout << "Passed key exchange\n\n";
}

int main(int argc, char ** argv){
  //check arguments
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <HOST> <PORT>" << std::endl;
    return EXIT_FAILURE;
  }

  //create a keys object
  ssh::Keys all_keys;

  //establish the connection, this part is taken from the real client for convenience
  int client = make_client(argv[1], argv[2]);
  if (client == -1){
    return EXIT_FAILURE;
  }

  //send a hello
  hello(client);

  //send and recive public keys
  keyex(client, all_keys);

  unsigned char u_id = '1';
  ssh::MsgType::Type msgType = ssh::MsgType::DEPOSIT;
  uint64_t money = 100;

  if (send(client, ssh::SendMsg(msgType, u_id, money, all_keys) , ssh::TOTAL_LEN, 0) < ssh::TOTAL_LEN) {
    perror("ERROR: Failed to send message");
    close(client);
    return -1;
  }
  char recvbuf[ssh::TOTAL_LEN] = {0};
  if (try_recv(client, recvbuf, ssh::TOTAL_LEN) == -1){
    close(client);
    return -1;
  }
}