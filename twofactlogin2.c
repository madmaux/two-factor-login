/*******************************************************************************
* file:        twofaclogin2.c
* author:      MQ
* description: PAM module to provide 2nd factor authentication
* compilation: gcc -fPIC -lcurl -c twofactlogin2.c
*	ld -lcurl -x --shared -o /lib/x86_64-linux-gnu/security/twofactlogin2.so twofactlogin2.o
*   or ld -lcurl -x --shared -o /lib/security/twofactlogin2.so twofactlogin2.o
* install if it's needed: 
*	build-essential libpam0g-dev libcurl4-openssl-dev
* usage: add this line to /etc/pam.d/lightdm or /etc/pam.d/common-auth to apply to all
* 	auth    required        twofactlogin.so
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <openssl/sha.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* 
* 
* expected hook 
*
*/
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/*
*
* generate token
*
*/
long genToken(char* passPhrase, int n) {
	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char salt[12];
	sprintf(salt, "%d%02d%02d%02d%02d", timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min + n);

	char* key = (char*)malloc(strlen(salt) + strlen(passPhrase) + 2);
	strcpy(key, salt);
	strncat(key, "'", 1);
	strncat(key, passPhrase, strlen(salt));
	strncat(key, "'", 1);

	unsigned char temp[SHA_DIGEST_LENGTH];
	memset(temp, 0x0, SHA_DIGEST_LENGTH);
	SHA1((unsigned char*)key, strlen(key), temp);
	free(key);

	char buf[SHA_DIGEST_LENGTH*2];
	memset(buf, 0x0, SHA_DIGEST_LENGTH*2);
	for (int i=0; i < SHA_DIGEST_LENGTH; i++)
		sprintf((char*)&(buf[i*2]), "%02x", temp[i]);

	char* start = &buf[strlen(buf)-15];
	char* end =  &buf[strlen(buf)];
	char buf2[16];
	buf2[15] = '\0';

	memcpy(buf2, start, end - start);
	
	long res = strtol(buf2, NULL, 16) % (long)pow(10, 6);
	
	return res;
}

/*
*
* this function is ripped from pam_unix/support.c, it lets us do IO via PAM 
*
*/
int converse(pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response) {
	int retval;
	struct pam_conv *conv;

	retval = pam_get_item(pamh, PAM_CONV, (const void **) &conv); 
	
	if (retval == PAM_SUCCESS) {
		retval = conv->conv(nargs, (const struct pam_message **) message, response, conv->appdata_ptr);
	}

	return retval;
}


/*
* Expected hook, where custom stuff happens 
*
*/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;
	int i;

	// To be used by converse()
	char *input;
	struct pam_message msg[1], *pmsg[1];
	struct pam_response *resp;

	// Retrieving parameters
	int got_pkey  = 0 ;
	char pkey[256];
	for( i=0; i < argc; i++ ) {
		if( strncmp(argv[i], "pkey=", 5) == 0) {
			strncpy(pkey, argv[i] + 5, 256) ;
			got_pkey = 1;
		}
	}
	if(got_pkey == 0)
		return PAM_AUTH_ERR ;

	// Getting the username that was used in the previous authentication
	const char *username;
	
	if ((retval = pam_get_user(pamh,&username,"login: ")) != PAM_SUCCESS)
		return retval;

	// Generating a random one-time code
	long token1 = genToken(pkey, 0);
	char code1[6];
	sprintf(code1, "%li", token1);
	
	// Setting up conversation call prompting for one-time code
	pmsg[0] = &msg[0];
	msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	msg[0].msg = "Token: ";
	resp = NULL;

	if ((retval = converse(pamh, 1 , pmsg, &resp)) != PAM_SUCCESS) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval;
	}

	// Retrieving user input
	if (resp) {
		if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
			free(resp);
			return PAM_AUTH_ERR;
		}
		input = resp[0].resp;
		resp[0].resp = NULL; 		  				  
	} else {
		return PAM_CONV_ERR;
	}

	// Comparing user input with known code
	if (strcmp(input, code1) == 0) {
		free(input);
		return PAM_SUCCESS;
	} else {
		free(input) ;
		return PAM_AUTH_ERR;
	}

	// We shouldn't read this point, but if we do, we might as well return something bad 
	return PAM_AUTH_ERR;
}
