#include <iostream>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <boost/thread/thread.hpp>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

static int auth_password(const char *user, const char *password){
    if(strcmp(user,"user"))
        return 0;
    if(strcmp(password,"111"))
        return 0;
    return 1; // authenticated
}


void thread_func(ssh_session session)
{
    ssh_message message;
    ssh_channel chan=0;
    char buf[2048];
    int auth=0;
    int sftp=0;
    int i;

    printf("Thread!");

    if (ssh_handle_key_exchange(session))
    {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return;
    }

    do
    {
        message=ssh_message_get(session);
        if(!message)
            break;
        switch(ssh_message_type(message))
        {
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message))
                {
                    case SSH_AUTH_METHOD_PASSWORD:
                        printf("User %s wants to auth with pass %s\n",
                               ssh_message_auth_user(message),
                               ssh_message_auth_password(message));
                        if(auth_password(ssh_message_auth_user(message),
                           ssh_message_auth_password(message)))
                        {
                               auth=1;
                               ssh_message_auth_reply_success(message,0);
                               break;
                           }
                        // not authenticated, send default message
                    case SSH_AUTH_METHOD_NONE:
                    default:
                        ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(message);
                        break;
                }
                break;
            default:
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (!auth);
    if(!auth)
    {
        printf("auth error: %s\n",ssh_get_error(session));
        ssh_disconnect(session);
        return;
    }

    do
    {
        message=ssh_message_get(session);
        if(message)
        {
            switch(ssh_message_type(message))
            {
                case SSH_REQUEST_CHANNEL_OPEN:
                    if(ssh_message_subtype(message)==SSH_CHANNEL_SESSION)
                    {
                        chan=ssh_message_channel_request_open_reply_accept(message);
                        break;
                    }
                default:
                ssh_message_reply_default(message);
            }
            ssh_message_free(message);
        }
    } while(message && !chan);

    if(!chan)
    {
        printf("error : %s\n",ssh_get_error(session));
        ssh_finalize();
        return;
    }
    do
    {
        message=ssh_message_get(session);
        if(message && ssh_message_type(message)==SSH_REQUEST_CHANNEL &&
           ssh_message_subtype(message)==SSH_CHANNEL_REQUEST_SHELL){
//            if(!strcmp(ssh_message_channel_request_subsystem(message),"sftp")){
                sftp=1;
                ssh_message_channel_request_reply_success(message);
                break;
 //           }
           }
        if(!sftp)
        {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (message && !sftp);

    if(!sftp)
    {
        printf("error : %s\n",ssh_get_error(session));
        return;
    }

    printf("it works !\n");

    do
    {
        i=ssh_channel_read(chan,buf, 2048, 0);
        if(i>0) {
            ssh_channel_write(chan, buf, i);
        }
    } while (i>0);

    ssh_disconnect(session);


}

using namespace std;

int main()
{
    ssh_bind sshbind;
    ssh_session session;
    int r;

    sshbind=ssh_bind_new();

    //ssh_session_set_blocking(session, )

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,       KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,       KEYS_FOLDER "ssh_host_rsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "2222");
    //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "3");

    if(ssh_bind_listen(sshbind)<0)
    {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }
    printf("listened\n");

    while(1)
    {
        session=ssh_new();

        r=ssh_bind_accept(sshbind, session);
        if(r==SSH_ERROR)
        {
          printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
          return 1;
        }

        printf("Accepted\n");

        boost::thread t(thread_func, session);

        //t.join();
    }

    ssh_bind_free(sshbind);

    ssh_finalize();

    return 0;
}

