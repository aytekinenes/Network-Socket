#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> 
#include <string.h>


#define PORT_NUMBER 4060
#define SERVER_BUF 1024
#define SAME 0


int main(){

    int sockFd;
    int acptSockFd;
    char buf[1024+1];
    struct sockaddr_in serverAddr;
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen;

    // Socket oluşturma
    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockFd == -1)
    {
        printf("error cannot create socket");
        exit(EXIT_FAILURE);
    }

    // Sunucu adresi ayarlama
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(4060); // 0 ile 1024 arasinda bir deger verme
    serverAddr.sin_addr.s_addr=  htonl(INADDR_ANY);

    // Bind işlemi (adres ve port bağlama)
    printf("Waiting for Client...\n");
    if(bind(sockFd,(struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    { 
        printf("error bind");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    //backlock kuyruguna gelen istekleri kabul edecegiz // Dinleme moduna geçiş (backlog 5)
    if(listen(sockFd,5) == -1)// FIFO kuyrugu
    {
        printf("error listen");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    // Bağlantı kabul etme
    clientAddrLen = sizeof(clientAddr);

    acptSockFd = accept(sockFd, (struct sockaddr*)&clientAddr, &clientAddrLen);

    if(acptSockFd == -1)
    {
        printf("error accept!!!");
        close(sockFd);
        exit(EXIT_FAILURE);
    }

    // Bağlanan istemci bilgilerini yazdırma
    printf("connected : %s port: %d\n" ,inet_ntoa(clientAddr.sin_addr),(uint16_t)ntohs(clientAddr.sin_port));
    
    char sendBuf[50];
   
   for(;;)
   {
    
        int res = recv(acptSockFd, buf, SERVER_BUF, 0);
        //sprintf(sendBuf, "Client Gonderdigin yazinin uzunlugu: %d",res);
        if(res <=0 ) break;
        puts(buf);

        int sendByte = send(acptSockFd, sendBuf, strlen(sendBuf), 0);

        if(strcmp(buf, "exit") == SAME)
            break;

        const char *response = "Message received";
        send(acptSockFd, response, strlen(response),0);

   }
   

    shutdown(sockFd,SHUT_RDWR);
    close(sockFd);
}