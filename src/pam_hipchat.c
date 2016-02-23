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
        /* +1 for the null terminator */
        int post_len = strlen(post_format)+strlen(auth_token)+strlen(from)+strlen(message)+5+1;
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
            //TODO: Log message here
            curl_easy_cleanup(curl);
            return -1;
        }
        
        /* always cleanup */ 
        curl_easy_cleanup(curl);
    } else {
        //TODO: Log message here
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

    char *server = NULL;
    char *dirty_token = NULL;
    char *token = NULL;
    char *auth_token = NULL;
    char *from = "PAM Login";
    bool debug=false;
    bool no_warn=false;
    bool no_verify_ssl=false;
    bool notify=false;
    
    /* root logged into server01 from server 02 */
    const char *message_format = "%s logged into %s from %s";
    char *message = NULL;
 
    const char* username = NULL;
    const char* rhost = NULL;
    char hostname[255];
    
    const char *default_hostname = "(unknown hostname)";
    const char *default_user = "(unknown user)";
    const char *default_rhost = "(unknown remote host)";
 
    /* parse module args */
    int i=0;
    for(i=0; i<argc; i++){
        //argv[] is a const char* and strtok modifies the original string
        //so we strdup so we can modify the string and free it at the end.
        char *term = strdup(argv[i]);
        
        //NULL here means that the token '=' was not detected in the string
        //therefore we look at the whole string as the token.
        dirty_token = strtok(term, "=");
        if(dirty_token == NULL){
            token = term;
        }else{
            token = trim(dirty_token);
        }
        
        
        //the second call to strtok with the first arg as NULL means 'give me the
        //next part of the tokenized string'
        if(strcmp(token,"server")==0){
            server = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"auth_token")==0){
            auth_token = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"from")==0){
            from = strdup(strtok(NULL,"="));
        }else if(strcmp(token,"debug")==0){
            //not used yet
            debug=true;
        }else if(strcmp(token,"no_warn")==0){
            //not used yet
            no_warn=true;
        }else if(strcmp(token,"no_verify_ssl")==0){
            //not used yet
            no_verify_ssl=true;
        }else if(strcmp(token,"notify")==0){
            notify=true;
        }/*else{
          //TODO: Log message here  
        }
        
        */
        free(term);
    }
    
    if(server == NULL || auth_token == NULL){
        //TODO: Log message here
        return PAM_SESSION_ERR;
    }
    
    
    //TODO: pan_get_item returns a lot of other things
    //  we should react in a more nuanced way.
    if(pam_get_item(pamh, PAM_USER, (const void **) &username) != PAM_SUCCESS){
        //TODO: Log message here
        username = default_user;
    }

    if(pam_get_item(pamh, PAM_RHOST, (const void **) &rhost) != PAM_SUCCESS){
        //TODO: Log message here
        rhost = default_rhost;
    }
    
    if(gethostname(hostname, 255) != 0){
        //TODO: Log message here
        strncpy(hostname, default_hostname, 255);
    }

    //+1 for the null terminator
    int message_len = strlen(username)+strlen(rhost)+strlen(hostname)+strlen(message_format)+1;
    message = malloc(message_len*sizeof(char));
    if(message == NULL){
        /* alloc failed */
        //TODO: Log message here
        return PAM_SESSION_ERR;
    }
    snprintf(message, message_len, message_format, username, hostname, rhost);

    int hipchat_ret = hipchat_send_message(server, auth_token, from, notify, message);
    if(hipchat_ret != 0){
        //TODO: log message here
        free(message);
        return PAM_SESSION_ERR;
    }

    free(message);
    return PAM_SUCCESS;
                                              
}
