/*
 * Socket.h
 *
 *  Created on: Sep 22, 2014
 *      Author: marshal
 */

#ifndef SOCKET_H_
#define SOCKET_H_
#include "bt_lib.h"
#include "bt_setup.h"


class Socket {
public:
	Socket();
	int createSocket();
	int bindToPort(peer_t *peer,int sock);
	int listenForConnections(int sock);
	int acceptConnections(int sock,sockaddr_in *clientAddr, unsigned int *clientAddrLength);
	int connectToSeeder(peer_t *peer,int sock,sockaddr_in *clientAddr, unsigned int *clientAddrLength);
	int sendMsg(int sock, char *msg);
	int recvMsg(int sock,char *msg, int len);

};

#endif /* SOCKET_H_ */
