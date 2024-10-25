#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> 

#define SERVER_PORT 4060
#define SERVER_IP "127.0.0.1"


int main()
{
    int sockFd;
    struct sockaddr_in clientAddr;
    
    sockFd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockFd == -1)
    {
        printf("error create socket \n");
        exit(EXIT_FAILURE);
    }
    else
        printf("socket succesfully created... \n");
    
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port= htons(SERVER_PORT);
    clientAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if(connect(sockFd,(struct sockaddr*)&clientAddr, sizeof(clientAddr)) == -1)
    {
        printf("error connect function!!! \n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully connection to server!!!! WELCOME");


    /*
        codes
    */

    shutdown(sockFd,SHUT_RDWR);
    close(sockFd);


}