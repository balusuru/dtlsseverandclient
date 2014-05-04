#ifndef _DTLS_API_H_
#define _DTLS_API_H_
/* OS related include files*/
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include "debug.h"

struct keys_hints
{
    unsigned char * key;
    unsigned char *hints;

}server, client;

int start_dtls_server(short listen_port);
int send_dtls_client_request(char* server_ip,  unsigned short port );
void init_DTLS(log_t loglev);

#define PRINTLOG(x) printf("\n %s \n",x)

#define PRINTF(...) printf(__VA_ARGS__)

#define DEFAULT_SERVER_PORT 20220
#define DEFAULT_CLIENT_PORT 20222
#define DEFAULT_PORT 20222

#endif
