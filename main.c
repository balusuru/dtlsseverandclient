
#include "dtls-server-client.h"
  int error;
/***** thread to start the server Remove once its done with PAL layer */
/**
 * print_message_function is used as the start routine for the threads used
 * it accepts a void pointer
**/
void startServer ( void *ptr )
{

     printf("\n ********************************** Started the server  ********************************** \n");
       error = start_dtls_server(DEFAULT_SERVER_PORT);
     printf("\n************************************* Closing the server  *******************************\n");

 }
int main(void)
{
 /**********************************************************************************************************
                    DTLS Client ENDS here
  *********************************************************************************************************/



    pthread_t thread1;

    init_DTLS(LOG_DEBUG);

   //q session_complete =0;
    char s_key[] = "secretPSK";
     char s_hint[] = "Client_identity";
     char c_key[] = "secretPSK";
      char c_hint[] = "Client_identity";

      server.key =  s_key ;
      server.hints =  s_hint ;
      client.key =  c_key ;
      client.hints =  c_hint ;

    error = send_dtls_client_request("127.0.0.1",DEFAULT_PORT);

    pthread_create (&thread1, NULL, (void *) &startServer, NULL);

    char d;

    PRINTF(" Send to enter");
    scanf(&d);

    error =  send_dtls_client_request("127.0.0.1",DEFAULT_PORT);




    PRINTF(" DTLS server waiting");
    while(1)
    {

    }
    return 0;


}


