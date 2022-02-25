#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string>
#include <stdlib.h>
#include "client.h"
#include "server.h"


void print_help(){
    std::cout << "\"usage: secret [-h] [-l] [-s HOSTNAME] [-r FILE]\\n\n"
                 "send encrypted files via ICMP\n\n"
                 "Options:\n"
                 "  -h          show this help message and exit\n"
                 "  -s NAME     specify servers IP/NAME\n"
                 "  -r FILE     specify file to send\n"
                 "  -l          enter server mode'\n"<< std::endl;
    exit(EXIT_SUCCESS);
}



int main(int argc,char **argv) {

    std::string fname,host;
    //arg parse
    if(argc == 1) {
        print_help();
    }
    for(int i=1;i<argc;i++){
        std::string arg(argv[i]);
        if(arg.compare("-h") == 0) {
            print_help();
        }
        else if(arg.compare("-l") == 0) {
            try {
                listen();
            } catch (const char* s) {
                std::cerr << s << std::endl;
                return EXIT_FAILURE;
            }
            return EXIT_SUCCESS;
        }
        else if(arg.compare("-r") == 0 && (i+1 < argc))
            fname = argv[++i];
        else if(arg.compare("-s") == 0 && (i+1 < argc))
            host = argv[++i];
        else
            return EXIT_FAILURE;
    }

    // (only client gets to this line) check args integrity
    if(fname.empty() || host.empty())
        return EXIT_FAILURE;

    //initialize client and try to send file
    try {
        Client cl(host, fname);
        cl.send_icmp();
    } catch (const char* s) {
        std::cerr << s << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
