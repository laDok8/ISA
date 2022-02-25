#include "server.h"
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <cstring>
#include <netinet/udp.h>
#include "network.h"
#include <map>
#include <set>
#include <pcap.h>
#include <cstdint>
#include <fstream>

std::map<uint16_t,std::ofstream *> hosts;
std::map<uint16_t,uint16_t> seq;
std::map<uint16_t,char *> fname;

#define SIZE_ETHERNET 14
#define SIZE_ICMP 8

//function processing each packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    struct ip *ip_recv = (struct ip *) (packet + SIZE_ETHERNET);
    u_int size_ip = ip_recv->ip_v==4 ? ip_recv->ip_hl*4 : 40;

    // načtení ICMP hlavičky
    struct icmp *icmp_recv = (icmp *) (packet + SIZE_ETHERNET + size_ip);
    if(icmp_recv->icmp_type != ICMP_ECHO)
        return;

    int recvLength=header->caplen;
    int dataLen = recvLength - SIZE_ETHERNET - size_ip - SIZE_ICMP - PROTOSIZE;

    //implemented procotol and data start
    packet_body *_start = (packet_body *)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);
    char *data = reinterpret_cast<char *>(&_start->data);

    //decrypt
    unsigned char tmp_bufout[MTU*3];
    int enclen = 0;
    try{
        enclen = decrypt(reinterpret_cast<unsigned char *>(data), dataLen,tmp_bufout);
    } catch  (const char* s) {
        //unknown communication caught -> skip
        return;
    }
    memcpy(data,&tmp_bufout,enclen);
    dataLen = enclen-_start->dropB;


    //if collision happens stop (both)
    if((_start->typ == packet_type::name && hosts.count(icmp_recv->icmp_id))){
        std::cerr <<  "halt: corrupted file " << std::endl;
        _start->typ = packet_type::end;
    }
    //check sequence error
    if(seq.count(icmp_recv->icmp_id) && (++seq[icmp_recv->icmp_id]) != icmp_recv->icmp_seq ) {
        std::cerr << "halt: sequence error"<< seq[icmp_recv->icmp_id] << " =/= " << icmp_recv->icmp_seq << std::endl;
        _start->typ = packet_type::end;
    }

    /*
     * proccess packet according to given type
     * name - create new file
     * data - write to the appropriate file
     * end  - close file
    */
    switch(_start->typ){
        case packet_type::name:
            char name[256];
            memcpy(name,data,dataLen);
            name[dataLen] = 0;
            hosts[icmp_recv->icmp_id] = new std::ofstream(name,std::ios::binary);
            fname[icmp_recv->icmp_id]= new char[dataLen]();
            memcpy(fname[icmp_recv->icmp_id],name,dataLen);
            seq[icmp_recv->icmp_id] = icmp_recv->icmp_seq;
            std::cout << "file: " << fname[icmp_recv->icmp_id] << " started" << std::endl;
            if(!hosts[icmp_recv->icmp_id])
                throw "cant open file";
            break;
        case packet_type::data :
            if(hosts.count(icmp_recv->icmp_id))
                hosts[icmp_recv->icmp_id]->write(data,dataLen);
            break;
        case packet_type::end :
            if(hosts.count(icmp_recv->icmp_id)) {
                std::cout << "file: " << fname[icmp_recv->icmp_id] << " ended" << std::endl;
                delete fname[icmp_recv->icmp_id];
                hosts[icmp_recv->icmp_id]->close();
                delete hosts[icmp_recv->icmp_id];
                fname.erase(icmp_recv->icmp_id);
                seq.erase(icmp_recv->icmp_id);
                hosts.erase(icmp_recv->icmp_id);
            }
            break;
    }

    return;
}

//initalize server for listening
void listen(){
    char ERRBUF[PCAP_ERRBUF_SIZE];
    pcap_if_t *allDevs;
    if(pcap_findalldevs(&allDevs,ERRBUF)==-1)
        throw "no listening devs found";

    //open interface for sniffing
    pcap_t *handle = pcap_open_live(allDevs->name, MTU, 1, 1, ERRBUF);
    if (!handle) {
        throw  "Couldn't open listening interface";
    }
    pcap_freealldevs(allDevs);


    //set pcap filter so only relevant packet are caught
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "icmp or icmp6", 1, (bpf_u_int32) 0) == -1)
        throw "Couldn't parse filter";

    if (pcap_setfilter(handle, &fp) == -1)
        throw "Couldn't install filter";

    //actual sniffing packet
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return;
}


