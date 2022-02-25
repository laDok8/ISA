#include <fstream>
#include <sys/socket.h>
#include "client.h"
#include "network.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netdb.h>
#include <unistd.h>

#define MINLEN 16

Client::Client(std::string host, std::string file){
    this->host = host;
    this->file = file;
}
//remove path component from file
std::string Client::getFileName(std::string filePath){
    if(filePath.rfind('/') != std::string::npos)
        return filePath.substr(filePath.rfind('/') + 1, filePath.size() - 1);
    return filePath;
}

//function sending data over network with additional code, that would be otherwise repeating
//such as: checksum calculation, encryption etc.
void Client::send(struct icmp * icmp_send,int sockfd,int dataLen){
    int headersLen =sizeof(struct icmp *)+PROTOSIZE;
    int packetlen = dataLen + headersLen;
    icmp_send->icmp_seq++;
    icmp_send->icmp_cksum = (uint16_t) 0;

    uint8_t *buffer;
    buffer = reinterpret_cast<uint8_t *>(icmp_send);
    packet_body *customPacket = reinterpret_cast<packet_body *>(buffer + sizeof(struct icmp *));
    uint8_t* data = reinterpret_cast<uint8_t *>(&customPacket->data);

    //encryption
    //if message is shorter than 16B we need to add zero padding
    customPacket->dropB=0;
    unsigned char tmpBuf[PAYLOAD];
    memset(&tmpBuf, 0, MINLEN);
    memcpy(&tmpBuf, data, dataLen);
    if(dataLen<MINLEN){
        customPacket->dropB=MINLEN-dataLen;
        dataLen=MINLEN;
    }
    int encLen = encrypt(tmpBuf, dataLen, data);
    packetlen = encLen + headersLen;

    //compute checksum and send
    icmp_send->icmp_cksum = checksum((unsigned char *) icmp_send, packetlen);
    usleep(100);
    if (sendto(sockfd, icmp_send, packetlen, 0,
               rp->ai_addr, rp->ai_addrlen) != packetlen)
        throw "sending data failed";

    //response check
    uint8_t packet_rcv[MTU];
    if (recv(sockfd, &packet_rcv, MTU, 0) == -1)
        throw "icmp_reply length mismatch";

}

void Client::send_icmp(){
    srand(time(NULL));
    uint16_t maxVal = -1;
    int sockfd=-1;
    uint16_t seq = rand()%maxVal, pid = rand()%maxVal;

    //open file
    std::ifstream fp(file, std::ios::binary);
    if(!fp)
        throw "file not found";
    file = getFileName(file);


    //initialize socket and receiver address
    struct addrinfo hint, *result;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_UNSPEC;
    hint.ai_socktype = SOCK_RAW;
    hint.ai_flags = AI_ALL;
    hint.ai_protocol = IPPROTO_ICMP;

    //resolve name/ip
    if (getaddrinfo(host.c_str(), NULL, &hint, &result) != 0)
        throw "hostname not resolvable";

    //open socket
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_family==AF_INET?IPPROTO_ICMP:IPPROTO_ICMPV6);
        if(sockfd != -1 )
            break;
    }
    if(sockfd==-1 )
        throw "socket creation error";

    //initialize memory for packets
    auto *packet = new uint8_t[MTU]();
    auto *icmp_send = (struct icmp *) packet;
    icmp_send->icmp_type = ICMP_ECHO;
    icmp_send->icmp_id = pid;
    icmp_send->icmp_seq = seq;

    packet_body *dataStart = reinterpret_cast<packet_body *>(packet + sizeof(icmp_send));

    //send file name
    dataStart->typ = packet_type::name;
    memcpy(&dataStart->data,file.c_str(),file.length());
    send(icmp_send,sockfd,file.length());

    // send date loop
    dataStart->typ = packet_type::data;
    while(!fp.eof()) {
        //fetch data
        fp.read(reinterpret_cast<char *>(&dataStart->data), PAYLOAD-sizeof(struct icmp *)-sizeof(struct ip6_hdr));
        send(icmp_send,sockfd,fp.gcount());
    }

    //send end confirmation
    dataStart->typ = packet_type::end;
    file="ok";
    memcpy(&dataStart->data,file.c_str(),file.length());
    send(icmp_send,sockfd,file.length());

    freeaddrinfo(result);
    delete[] packet;
    return;
}
