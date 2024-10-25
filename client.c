#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> 

#define SERVER_PORT 4060
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024
#define SAME 0

char* stringGets(char *p);

int main() {
    int sockFd;
    struct sockaddr_in clientAddr;
    char buf[BUFFER_SIZE + 1];
    char recvBuf[BUFFER_SIZE + 1];  // Sunucudan alınacak veriyi depolamak için

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd == -1) {
        printf("error create socket \n");
        exit(EXIT_FAILURE);
    } else {
        printf("socket successfully created... \n");
    }

    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(SERVER_PORT);
    clientAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sockFd, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) == -1) {
        printf("error connect function!!! \n");
        exit(EXIT_FAILURE);
    }

    printf("Successfully connected to server!!!! WELCOME\n");

    for (;;) {
        // Kullanıcıdan mesaj al ve sunucuya gönder
        stringGets(buf);
        int sendByte = send(sockFd, buf, strlen(buf), 0);
        printf("Sent bytes: %d\n", sendByte);

        // Eğer "exit" gönderildiyse döngüyü sonlandır
        if (strcmp(buf, "exit") == SAME)
            break;

        // Sunucudan yanıtı al
        int recvByte = recv(sockFd, recvBuf, BUFFER_SIZE, 0);
        if (recvByte > 0) {
            recvBuf[recvByte] = '\0'; // Sonlandırıcı ekle
            printf("Received from server: %s\n", recvBuf);
        } else {
            printf("No response from server or connection closed.\n");
            break;
        }
    }

    shutdown(sockFd, SHUT_RDWR);
    close(sockFd);
    return 0;
}

char* stringGets(char *p) {
    int c;
    char *pTemp = p;
    while ((c = getchar()) != '\n')
        *p++ = (char)c;

    *p = '\0';
    return pTemp;
}
