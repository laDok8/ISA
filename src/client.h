
#ifndef ISA_CLIENT_H
#define ISA_CLIENT_H

#include <string>
#include <netinet/in.h>

class Client {
private:
    std::string host,file;
    void send(struct icmp * icmp_send,int sockfd,int packetlen);
    std::string getFileName(std::string filePath);
    struct addrinfo *rp;

public:
    Client(std::string host, std::string file);
    void send_icmp();

};

#endif //ISA_CLIENT_H
