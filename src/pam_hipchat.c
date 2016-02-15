#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <curl/curl.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>


typedef enum { false, true } bool;

/*

TODO:
    add debugging code
    add warning code
    code comments
*/


char *rtrim(const char *s)
{
  while( isspace(*s) || !isprint(*s) ) ++s;
  return strdup(s);
}
 

char *ltrim(const char *s)
{
  char *r = strdup(s);
  if (r != NULL)
  {
    char *fr = r + strlen(s) - 1;
    while( (isspace(*fr) || !isprint(*fr) || *fr == 0) && fr >= r) --fr;
    *++fr = 0;
  }
  return r;
}

char *trim(const char *s)
{
  char *r = rtrim(s);
  char *f = ltrim(r);
  free(r);
  return f;
}


int hipchat_send_message(char *server, char *auth_token, char *from, bool notify, char *message){

    CURL *curl;
    CURLcode res;
    const char *post_format = "auth_token=%s&from=%s&message_format=text&notify=%s&message=%s";
    char *post_data;

    curl_global_init(CURL_GLOBAL_ALL);
    
    curl = curl_easy_init();
    if(curl) {

        curl_easy_setopt(curl, CURLOPT_URL, server);

        /* 5 is the longer of "true" and "false" */
        int post_len = strlen(post_format)+strlen(auth_token)+strlen(from)+strlen(message)+5;
        post_data = malloc(post_len*sizeof(char));
        
        if(post_data == NULL){
            return -1;
        }
        
        snprintf(post_data, post_len, post_format, auth_token, from, notify?"true":"false", message);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
        
        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if(res != CURLE_OK){
            curl_easy_cleanup(curl);
            return -1;
        }
        
        /* always cleanup */ 
        curl_easy_cleanup(curl);
    } else {
        return -1;
    }
    
    curl_global_cleanup();
    free(post_data);
    return 0;
    
}

/* expected hook, PAM complains if we use this as a session module and can't resolve this symbol */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                          int argc, const char **argv) {

    return PAM_SUCCESS;

}

/* expected hook */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                          int argc, const char **argv) {


    char *server;
    char *dirty_token;
    char *token;
    char *auth_token;
    char *from = "PAM Login";
    int debug=0;
    int no_warn=0;
    int no_verify_ssl=0;
    bool notify=false;
    
    /* root logged into server01 from server 02 */
    const char *message_format = "%s logged into %s from %s";
    char *message;
 
    const char* username;
    const char* rhost;
    char hostname[255];
    
    const char *default_hostname = "(unknown hostname)";
    const char *default_user = "(unknown user)";
    const char *default_rhost = "(unknown remote host)";
 
    /* parse module args */
    int i=0;
    for(i=0; i<argc; i++){
        char *term = strdup(argv[i]);
        dirty_token = strtok(term, "=");
        if(dirty_token == NULL){
            token = term;
        }else{
            token = trim(dirty_token);
        }
        
        if(strcmp(token,"server")==0){
            server = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"auth_token")==0){
            auth_token = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"from")==0){
            from = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"debug")==0){
            debug=1;
        }else if(strcmp(token,"no_warn")==0){
            no_warn=1;
        }else if(strcmp(token,"no_verify_ssl")==0){
            no_verify_ssl=1;
        }else if(strcmp(token,"notify")==0){
            notify=true;
        }
        
        free(term);
    }
    
    if(pam_get_item(pamh, PAM_USER, (const void **) &username) != PAM_SUCCESS){
        username = default_user;
    }

    if(pam_get_item(pamh, PAM_RHOST, (const void **) &rhost) != PAM_SUCCESS){
        rhost = default_rhost;
    }
    
    if(gethostname(hostname, 255) != 0){
        strncpy(hostname, default_hostname, 255);
    }

    int message_len = strlen(username)+strlen(rhost)+strlen(hostname)+strlen(message_format);

    message = malloc(message_len*sizeof(char));
    if(message == NULL){
        /* alloc failed */
        return PAM_SESSION_ERR;
    }
    
    snprintf(message, message_len, message_format, username, hostname, rhost);

    int hipchat_ret = hipchat_send_message(server, auth_token, from, notify, message);
    if(hipchat_ret != 0){
        free(message);
        return PAM_SESSION_ERR;
    }

    free(message);
    
    return PAM_SUCCESS;
                                              
}
