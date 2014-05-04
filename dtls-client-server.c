
#include <signal.h>
/* DTLS  realted include files*/
#include "config.h"
#include "dtls.h"
#include "debug.h"
#include "dtls-server-client.h"



static dtls_context_t *server_context = NULL;
dtls_context_t *dtls_client_context = NULL;
static session_t client_dst;
static int fdc, fds;
static session_t s_session;
  fd_set crfds;

static fd_set srfds;
/**********************************************************************************************************

                    DTLS Server Starts Here

*********************************************************************************************************/

char * che = "Client_identity";
/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int
get_key_server(struct dtls_context_t *ctx,
    const session_t *session,
    const unsigned char *id, size_t id_len,
    const dtls_key_t **result) {

  static  dtls_key_t psk = {
    .type = DTLS_KEY_PSK,
    //.key.psk.id = (unsigned char *)"Client_identity",
  };

    psk.key.psk.id = (unsigned char *)server.hints;
    psk.key.psk.id_length = strlen(server.hints);
    psk.key.psk.key = (unsigned char *)server.key;
    psk.key.psk.key_length = strlen(server.key);
  *result = &psk;
  return 0;
}

int
read_from_peer_client(struct dtls_context_t *ctx,
           session_t *session, uint8 *data, size_t len) {
  size_t i;
  static int ii =0;
  printf("\n%s for %d\n", "Recived the data ",ii);
  for (i = 0; i < len; i++)
    printf("%c", data[i]);
  char  a = 'A' +ii ;
  ii++;
  return dtls_write(ctx, session, &a, 1);
}

int
send_to_peer_client(struct dtls_context_t *ctx,
         session_t *session, uint8 *data, size_t len) {

  int fd = *(int *)dtls_get_app_data(ctx);
  return sendto(fd, data, len, MSG_DONTWAIT,
        &session->addr.sa, session->size);
}

int
dtls_handle_read(struct dtls_context_t *ctx) {

  int *fd;

  static uint8 sbuf[DTLS_MAX_BUF];
  int len;

  if(ctx == NULL)
  {
      PRINTF("\nContext is null so exit\n");
      exit(0);

  }
  fd = dtls_get_app_data(ctx);

  assert(fd);

  s_session.size = sizeof(s_session.addr);
  len = recvfrom(fds, sbuf, sizeof(sbuf), 0,
         &s_session.addr.sa, &s_session.size);

  if (len < 0) {
    perror("recvfrom");
    return -1;
  } else {
    dsrv_log(LOG_DEBUG, "got %d bytes from port %d\n", len,
         ntohs(s_session.addr.sin6.sin6_port));
  }

  return dtls_handle_message(ctx, &s_session, sbuf, len);
}

int
resolve_address(const char *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error;

  memset(addrstr, 0, sizeof(addrstr));
  if (server && strlen(server) > 0)
    memcpy(addrstr, server, strlen(server));
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, "", &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:

      memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
      return ainfo->ai_addrlen;
    default:
      ;
    }
  }

  freeaddrinfo(res);
  return -1;
}



static dtls_handler_t server_cb = {
  .write = send_to_peer_client,
  .read  = read_from_peer_client,
  .event = NULL,
  .get_key = get_key_server
};

int
start_dtls_server(short listen_port) {


  struct timeval timeout;
  int  result;
  int on = 1;
  struct sockaddr_in6 listen_addr;

  memset(&listen_addr, 0, sizeof(struct sockaddr_in6));

  /* fill extra field for 4.4BSD-based systems (see RFC 3493, section 3.4) */
#if defined(SIN6_LEN) || defined(HAVE_SOCKADDR_IN6_SIN6_LEN)
  listen_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif

  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(listen_port);
  listen_addr.sin6_addr = in6addr_any;



  /* init socket and set it to non-blocking */
  fds = socket(listen_addr.sin6_family, SOCK_DGRAM, 0);

  if (fds < 0) {
    dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
    return 0;
  }

  if (setsockopt(fds, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) ) < 0) {
    dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
  }


  if (bind(fds, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
    dsrv_log(LOG_ALERT, "bind: %s\n", strerror(errno));
    goto error;
  }


  server_context = dtls_new_context(&fds);

  dtls_set_handler(server_context, &server_cb);

  while (1) {
    FD_ZERO(&srfds);


    FD_SET(fds, &srfds);
    /* FD_SET(fd, &wfds); */

    timeout.tv_sec = 50;
    timeout.tv_usec = 0;

    result = select( fds+1, &srfds, NULL, 0, &timeout);

    if (result < 0) {		/* error */
      if (errno != EINTR)
    perror("select");
    } else if (result == 0) {
        printf("Time Out in server ********************************************************************");
        /* timeout */
    }
        if (FD_ISSET(fds, &srfds)) {
    int er = dtls_handle_read(server_context);
    //if(er<0) goto error;
      }
    }


 error:
  printf("\nRecived Error\n");
  dtls_free_context(server_context);
  return -1;

}
/**********************************************************************************************************

                    DTLS Server Ends Here

*********************************************************************************************************/

/**********************************************************************************************************

                    DTLS Client Starts Here

*********************************************************************************************************/


extern size_t dsrv_print_addr(const session_t *, unsigned char *, size_t);

static char buf[200];
static size_t len = 0;


int session_complete = 0;

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int get_client_key(struct dtls_context_t *ctx, const session_t *session,
        const unsigned char *id, size_t id_len, const dtls_key_t **result) {
    PRINTLOG("get_client_key");

    static  dtls_key_t psk = {
        .type = DTLS_KEY_PSK,
    };
    psk.key.psk.id = (unsigned char *)client.hints;
    psk.key.psk.id_length = strlen(client.hints);
    psk.key.psk.key = (unsigned char *)client.key;
    psk.key.psk.key_length = strlen(client.key);

    *result = &psk;
    return 0;
}


int dtls_handle_read_client(struct dtls_context_t *ctx) {
    PRINTLOG("dtls_handle_read");

    session_t session;
#define MAX_READ_BUF 2000
    static uint8 buf[MAX_READ_BUF];
    int len;

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(fdc, buf, MAX_READ_BUF, 0, &session.addr.sa, &session.size);

    if (len < 0) {
        perror("recvfrom");
        return -1;
    }

    return dtls_handle_message(ctx, &session, buf, len);
}

void try_send(struct dtls_context_t *ctx, session_t *dst) {
    PRINTLOG("try_send");
    int res;
    res = dtls_write(ctx, dst, (uint8 *) buf, len);
    if (res >= 0) {
        memmove(buf, buf + res, len - res);
        len -= res;
    }
}



int send_client_data(struct dtls_context_t *ctx, session_t *dst)
{
    len = 14;
    sprintf(buf,"\n Client data %d",len);
    try_send(ctx, dst);
    dtls_handle_read_client(ctx);
return 0;
}

/* this will be used by tinyDTLS to notifu the application whenever DTLS session has changed
 Currently, the only defined internal event is DTLS_EVENT_CONNECTED. It indicates successful
 establishment of a new DTLS channel.. */
int handle_event(struct dtls_context_t *ctx, session_t *session,
dtls_alert_level_t level, unsigned short code) {

    switch(code)
    {
    case DTLS_EVENT_CONNECTED:
        PRINTF("DTLS session intiation succesful");
        session_complete = 1;
        send_client_data(ctx, session);
        break;
    }

return 0;
}




int read_from_peer_server(struct dtls_context_t *ctx,
session_t *session, uint8 *data, size_t len) {
    PRINTLOG("read_from_peer_serevr");
    size_t i;
    for (i = 0; i < len; i++)
        printf("%c", data[i]);
    return 0;
}

int send_to_peer_server(struct dtls_context_t *ctx,
session_t *session, uint8 *data, size_t len) {

    PRINTLOG("send_to_peer_serevr");
    int fd = *(int *) dtls_get_app_data(ctx);
    return sendto(fd, data, len, MSG_DONTWAIT, &session->addr.sa, session->size);
}

#ifndef NDEBUG
extern void dump(unsigned char *buf, size_t len);
#endif


static dtls_handler_t client_cb = { .write = send_to_peer_server, .read = read_from_peer_server,
        .event = handle_event, .get_key = get_client_key };

int send_dtls_client_request(char* server_ip,  unsigned short port ) {

    session_complete =0;
    struct timeval timeout;
    char port_str[NI_MAXSERV] = "0";

    int  result, on = 1, res;



    snprintf(port_str, sizeof(port_str), "%d", port);


    memset(&client_dst, 0, sizeof(session_t));
    /* resolve destination address where server should be sent */
    res = resolve_address(server_ip, &client_dst.addr.sa);

    if (res < 0) {
        dsrv_log(LOG_EMERG, "failed to resolve address\n");
        return -1;
    }
    client_dst.size = res;

    /***/
    /* use port number from command line when specified or the listen
     port, otherwise */
    client_dst.addr.sin.sin_port = htons(port);

    /* init socket and set it to non-blocking */
    fdc = socket(client_dst.addr.sa.sa_family, SOCK_DGRAM, 0);

    if (fdc < 0) {
        dsrv_log(LOG_ALERT, "socket: %s\n", strerror(errno));
        return 0;
    }

    if (setsockopt(fdc, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        dsrv_log(LOG_ALERT, "setsockopt SO_REUSEADDR: %s\n", strerror(errno));
    }

    dtls_client_context = dtls_new_context(&fdc);
    if (!dtls_client_context) {
        dsrv_log(LOG_EMERG, "cannot create context\n");
        return -1;
    }

    dtls_set_handler(dtls_client_context, &client_cb);

    dtls_connect(dtls_client_context, &client_dst);

    while (session_complete == 0 ) {

        FD_ZERO(&crfds);

        FD_SET(fdc, &crfds);
        /* FD_SET(fd, &wfds); */
        printf("\nEntred the while loop  %d \n", fdc);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        result = select(fdc + 1, &crfds, 0, 0, &timeout);

        if (result < 0) { /* error */
            if (errno != EINTR)
                perror("select");
        } else if (result == 0) {
            /* timeout */
            printf("\nTimed out \n");
            break;
        } else {
             if (FD_ISSET(fdc, &crfds))
                dtls_handle_read_client(dtls_client_context);
                    }
        printf("\nEntred after while loop  %d \n", fdc);

    }

   //dtls_free_context(dtls_client_context);


return 0;
}

void init_DTLS( log_t loglev)
{
    dtls_set_log_level(loglev);
    dtls_init();
}
