#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>

#define BUFLEN 1024

char *filename;

static void process(char *cmd, char *filename);
static void cleanup(void);

void process(char *cmd, char *filename)
{
    const char *path = RESOLVCONF;
    pid_t pid;
    int pipefd[2];

    if (pipe(pipefd) < 0)
    {
        syslog(LOG_ERR, "Error from pipe(). Terminating.");
        exit(1);
    }
    
    pid = fork();
    if (-1 == pid)
    {
        syslog(LOG_ERR, "Error from fork(). Terminating.");
        exit(1);
    }
    else if (0 == pid)
    {
        /* In the child */

        /* Close unused write end of pipe. */
        close(pipefd[1]);       

        /* Connect stdin to the pipe's read end. */
        if (-1 == dup2(pipefd[0], 0))
        {
            syslog(LOG_ERR, "Error from dup2(). Terminating child.");
            exit(1);
        }
    
        /* Start resolvconf. */
        if (-1 == execl(path, "resolvconf", cmd, "radns", NULL))
        {
            syslog(LOG_ERR, "Error from execl(). Terminating child.");
            exit(1);
        }
    }
    else
    {
        int fd;
        ssize_t len;
        char buf[BUFLEN];

        /* Parent. */

        /* Close unused read end of pipe. */  
        close(pipefd[0]);

        /* Feed the kid our resolv.conf file. */
        if (0 > (fd = open(filename, O_RDONLY)))
        {
            syslog(LOG_ERR, "Error from open().");
            goto end;
        }

        do
        {
            len = read(fd, &buf, BUFLEN);

            if (len < 0)
            {
                syslog(LOG_ERR, "Error from read() when reading resolv file.");
                goto end;
            }
            else if (len > 0)
            {
                if (len != write(pipefd[1], buf, len))
                {
                    syslog(LOG_ERR, "Error from write().");
                    goto end;
                }
            }
        }
        while(len > 0);

    end:
        close(fd);
        
        /* Close write end, signifying end of file to child. */
        close(pipefd[1]);

        /* Wait for the child to exit. */
        wait(NULL);
    }
    
}

void cleanup(void)
{
    syslog(LOG_INFO, "EOF or error on pipe. Cleaning up and "
           "terminating.\n");
    syslog(LOG_INFO, "Deleting DNS server.\n");            
    process("-d", filename);
}

int main(int argc, char **argv)
{
    char cmd;
    ssize_t len;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: raresolv filename.\n");
        exit(1);
    }

    filename = argv[1];

    signal(SIGPIPE, SIG_IGN);
    
    openlog(argv[0], LOG_PID | LOG_NDELAY, LOG_DAEMON);
    
    for (;;)
    {
        len = read(0, &cmd, 1);
        if (len <= 0)
        {
            cleanup();
            exit(1);
        }
        else
        {
            switch (cmd)
            {
            case '+':
                syslog(LOG_INFO, "Adding DNS server.\n");
                process("-a", filename);
                break;

            case '-':
                syslog(LOG_INFO, "Deleting DNS server.\n");
                process("-d", filename);
                break;

            default:
                syslog(LOG_INFO, "Received unknown command from pipe.\n");
                /* Unknown command. Just ignore it. */
                break;
            }
        }
    }

    exit(0);
}
