#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <paths.h>


char* exe;
char* R;
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

extern char** environ;


void* open(char* s) {
    FILE *fp;

    int pdes[2];
    if (pipe(pdes))
        err(1, "pipe");

    const char* mode = "r";

    char* exeargv[] = {exe, R, NULL};
    int pid;
    switch (pid=fork()) {
        case 0:
           close(pdes[0]);
           dup2(pdes[1], 1);
           close(pdes[1]);
           execve(exeargv[0], exeargv, environ);
           err(1, "execve");  /* exec does not return except on error */
           break;
        default:
           close(pdes[1]);
           fp = fdopen(pdes[0], mode);
           if (fp == NULL)
                err(1, "fdopen");
           return fp;
    }
}

void* spawn(void* _) {
    char s[64];  /* small buffer intentional */
    FILE *fp;

   fp = open(exe);

    while (fgets(s, sizeof(s)-1, fp) != NULL) {
        pthread_mutex_lock(&m);
        printf("%s", s); fflush(stdout);
        pthread_mutex_unlock(&m);
    }

    fclose(fp);
    return NULL;
}

int main( int argc, char *argv[] )
{
    exe = argv[1];
    int N = atoi(argv[2]);
    R = argv[3];

  /* Open the command for reading. */
    pthread_t ts[N];

    for (int k = 0; k < N; k++)
        pthread_create(&ts[k], NULL, *spawn, (void*)NULL);

    for (int k = 0; k < N; k++)
        pthread_join(ts[k], NULL);
    return 0;
}
