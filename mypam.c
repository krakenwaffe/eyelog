#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval;

	const char* pUsername;
	retval = pam_get_user(pamh, &pUsername, "User: ");
	char *input;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;

	// disallow root logins
	if (strcmp(pUsername, "root") == 0) {
		return PAM_AUTH_ERR;
	}


	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
	msg[0].msg = "The password: " ;
	resp = NULL;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		return retval ;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
	    		free( resp );
	    		return PAM_AUTH_ERR;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL; 		  				  
    	} else {
		return PAM_CONV_ERR;
	}

	
	time_t now = time(NULL);
	struct tm *now_tm = localtime(&now);
	int hour = now_tm->tm_hour;
	int day = now_tm->tm_mday;

	char correctPass[11];
	sprintf(correctPass, "daypass%d%d", day, hour);
		

	if(strcmp(correctPass, input)==0) {
		return PAM_SUCCESS;
	}
	else
		return PAM_AUTH_ERR;


	if (retval != PAM_SUCCESS) {
		return retval;
	}

	return PAM_AUTH_ERR;
}
