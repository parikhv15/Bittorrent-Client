/*
 * Socket.cpp
 *
 *  Created on: Sep 22, 2014
 *      Author: marshal
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include "Socket.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include <iostream>

using namespace std;

Socket::Socket() {
	// TODO Auto-generated constructor stub
}

int Socket::createSocket(){
	int sock=0;
	if((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))<0){
	fprintf(stderr,"ERROR: Socket could not be created.\n");
	exit(1);
	}
	else{
		return sock;
	}



}

int Socket::bindToPort(peer_t *peer,int sock){
	if((bind(sock,(struct sockaddr*)&(peer->sockaddr),sizeof(peer->sockaddr)))<0)
		return -1;
	else
		return 1;
	}

int Socket::listenForConnections(int sock){
	if((listen(sock,MAX_CONNECTIONS-1))<0)
		return -1;
	else
		return 1;

}
int Socket::acceptConnections(int sock,sockaddr_in *peerAddr, unsigned int *peerAddrLength){
	//struct sockaddr_in peerAddr;
	//unsigned int peerSockLen=sizeof(peerAddr);
	int peerSock=accept(sock,(struct sockaddr*)peerAddr,peerAddrLength);
		if(peerSock<0)
			return -1;
		else{
			//cout<<clientAddr->sin_port<<" " << inet_ntoa(clientAddr->sin_addr)<<endl;
			return peerSock;
}
}

int Socket::connectToSeeder(peer_t *peer,int sock,sockaddr_in *addr, unsigned int *addrLength){
	if(connect(sock, (struct sockaddr*) &peer->sockaddr, sizeof(peer->sockaddr)) < 0)
	return -1;
	else{
		if(getsockname(sock,(sockaddr*)addr,addrLength)==0){

		   //cout<<"Success"<<endl;
		   return 1;
		}
		else{
			cout<<"error"<<endl;
			return -1;
		}
	}
		//return getsockname(sock,clientAddr,clientAddrLength);
		//return 1;
}
int Socket::sendMsg(int sock, char *msg){
	//cout<<strlen(msg)<<endl;
	if(send(sock,msg,strlen(msg),0)<0){
		return -1;
	}
	else{
		return 1;
	}
}

int Socket::recvMsg(int sock,char *msg, int len){

	int bytesRcvd=0;
	//int totalBytesRcvd=0;
	bytesRcvd=recv(sock,msg,len,0);

	if(bytesRcvd<0){
		return -1;
	}
	//cout<<"BytesRcvd::"<<bytesRcvd<<endl;
	if(bytesRcvd>0){
		//cout<<"BytesRcvd::"<<bytesRcvd<<endl;
		return bytesRcvd;
	}
	else{
		return bytesRcvd;
	}
	/*else{
		return 1;
	}*/
}
