/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include <errno.h>

/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16



void sighandler() {
	signal(SIGINT, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	printf("Signal ignored \n");
}
void printLoginFail(){
	printf("Login Incorrect \n");
}
int main(int argc, char *argv[]) {

	mypwent *passwddata;
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		/* 
		Use fgets to protect from buffer overflows, 
		buffer reads length bytes from input and discards the rest. 
		*/
		if (fgets(user,LENGTH,stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */
		user[strcspn(user, "\n")] = '\0';
		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		/* Get inputted password */
		user_pass = getpass(prompt);
		/* Get saved account information */
		passwddata = mygetpwnam(user);
		
		if (passwddata != NULL) {
			/* 
			Safe guard against multiple failed logins
			However this introduces the problem that an adversary
			could potentially target accounts and lock them by
			knowing just the username 
			*/
			if(passwddata->pwfailed > 3){
				printLoginFail();
				continue;
			}
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			/* encrypt the input password with the salt and then compare */
			c_pass = crypt(user_pass,passwddata->passwd_salt);
			if (strcmp(c_pass,passwddata->passwd) == 0) {
				printf(" Previous fails: %d\n",passwddata->pwfailed);
				/* Reset pwfailed and increment age */
				passwddata->pwfailed = 0;
				passwddata->pwage += 1;
				if(passwddata->pwage >= 10){
					printf("You should change your password bro\n");
				}
				/* Update passwddata */
				mysetpwent(passwddata->pwname,passwddata);
				printf("You're in! \n");

				/*  check UID, see setuid(2) */
				/* Set uid and check retrun values */
				int setUidResult = setuid(passwddata->uid);
				if(setUidResult == -1 ){
					printf("SetUid failed, errno: %d \n",errno);
					/* Perror will exit the program and print an intelligible reason */
					perror("setuid");
				}else {
					printf("Sucessfully set uid\n");
				}
				/*  start a shell, use execve(2) */
				char *args[] = {"/bin/sh",NULL};
				char *env[] = {NULL};
				/* Execute shell and check retrun values */
				int execShellResult = execve("/bin/sh",args,env);
				if(execShellResult == -1 ){
					printf("Exec shell failed, errno: %d\n",errno);
					/* Perror will exit the program and print an intelligible reason */
					perror("execve");
				}else {
					printf("Sucessfully executed shell\n");
				}
				

			} else {
				/* Incorrect password, increment pwfailed and update */
				passwddata->pwfailed += 1;
				mysetpwent(passwddata->pwname,passwddata);
				printLoginFail();
			}
		}else {
			printf("User not found \n");
		}
	}
	return 0;
}


