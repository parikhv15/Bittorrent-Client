#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include<fstream>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces
#include "Socket.h"
#include "bt_lib.h"
#include "bt_setup.h"
#include <math.h>

using namespace std;

#define TEMPLEN 1024
#define SHA_DIGEST_LENGTH 20

//Method to parse torrent file.
int parse_bt_info(bt_info_t * bt_info, bt_args_t bt_args, char* infohash) {
	FILE *ip;
	int i = 0, x = 0, t = 0, y = 0, info = 0;
	char temp[TEMPLEN];
	char key[TEMPLEN];

	ip = fopen(bt_args.torrent_file, "r");

	fseek(ip, 0L, SEEK_END);
	int sizeOfFile = ftell(ip);
	fseek(ip, 0L, SEEK_SET);

	char* infod;
	char* buf;

	infod = (char*) malloc(sizeOfFile);
	buf = (char*) malloc(sizeOfFile + 2);
	bt_info->piece_hashes = (char **) malloc((SHA_DIGEST_LENGTH * 40));

	fread(buf, 1, sizeOfFile, ip);
	buf[sizeOfFile] = '\0';
	while (i != sizeOfFile - 1) {
		//printf("Hello");
		switch (*(buf + i)) {
		case 'd':
			i++;
			break;

		case ':':
			i++;
			while (x < t) {
				temp[x] = *(buf + i);
				x++;
				i++;
			}
			temp[x] = '\0';

			if (strcmp(key, "name") == 0) {
				memcpy(bt_info->name, temp, strlen(temp));
				bt_info->name[strlen(temp)] = '\0';
			}
			if (strcmp(temp, "info") == 0) {
				info = i;
			}
			x = 0;
			if (strcmp(key, "pieces") == 0) {
				while (x < t - 20) {
					*(bt_info->piece_hashes + y) = (char *) malloc(
					SHA_DIGEST_LENGTH);
					memcpy(*(bt_info->piece_hashes + y), &temp[x],
					SHA_DIGEST_LENGTH);
					x = x + 20;
					y++;
				}
				*(bt_info->piece_hashes + y) = (char *) malloc(
				SHA_DIGEST_LENGTH);
				memcpy(*(bt_info->piece_hashes + y), &temp[x],
				SHA_DIGEST_LENGTH);
			}

			memset(key, 0, strlen(key));
			strcpy(key, temp);
			x = 0;
			memset(temp, 0, strlen(temp));
			break;

		case 'i':
			i++;
			while (*(buf + i) != 'e') {
				temp[x] = *(buf + i);
				x++;
				i++;
			}
			if (strcmp(key, "length") == 0) {
				bt_info->length = atoi(temp);
			} else if (strcmp(key, "piece length") == 0) {
				bt_info->piece_length = atoi(temp);
			}
			i++;
			x = 0;
			memset(temp, 0, strlen(temp));
			break;

		case 'e':
			i++;
			break;

		default:
			if (isdigit((unsigned char) buf[i])) {
				while (*(buf + i) != ':') {
					temp[x] = *(buf + i);
					x++;
					i++;
				}
				t = atoi(temp);
				//printf("%d \n", t);
				x = 0;
				memset(temp, 0, strlen(temp));
			}
			break;
		}
	}

	x = 0;
	if (*(buf + info) == 'd') {

		info++;
		while (!(*(buf + info) == 'e' && *(buf + info + 1) == 'e'
				&& *(buf + info + 2) == '\0')) {
			infod[x] = buf[info];
			info++;
			x++;
		}
		infod[x] = '\0';

		SHA1((unsigned char*) infod, strlen(infod), (unsigned char*) infohash);

		bt_info->num_pieces = (bt_info->length / bt_info->piece_length) + 1;
	}
	fclose(ip);
	free(infod);
	free(buf);
	return 0;
}

void calc_id(char * ip, unsigned short port, char *id) {
	//cout<<"Inside calc_id"<<endl;
	char data[256];
	int len;

	//format print
	len = snprintf(data, 256, "%s%u", ip, port);

	//id is just the SHA1 of the ip and port string
	SHA1((unsigned char *) data, len, (unsigned char *) id);
	//id[SHA_DIGEST_LENGTH] = '\0';
//cout<<strlen(id)<<endl;
	return;
}

/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port) {
	//cout<<"Inside init_peer"<<endl;
	struct hostent * hostinfo;
	//set the host id and port for referece
	memcpy(peer->id, id, ID_SIZE);
	peer->port = port;

	//get the host by name
	if ((hostinfo = gethostbyname(ip)) == NULL) {
		perror("gethostbyname failure, no such host?");
		herror("gethostbyname");
		exit(1);
	}

	//zero out the sock address
	bzero(&(peer->sockaddr), sizeof(peer->sockaddr));

	//set the family to AF_INET, i.e., Iternet Addressing
	peer->sockaddr.sin_family = AF_INET;

	//copy the address to the right place
	bcopy((char *) (hostinfo->h_addr),
	(char *) &(peer->sockaddr.sin_addr.s_addr),
	hostinfo->h_length);
	//encode the port
	peer->sockaddr.sin_port = htons(port);

	return 0;

}

//Function to add peer to peer array.
int add_peer(peer_t *peer, sockaddr_in *peerAddr) {

	memset(peer, 0, sizeof(peer_t));
	char * id;

	id = (char*) malloc(ID_SIZE * sizeof(char));

	peer->choked = 1;
	peer->interested = 0;

	bcopy((sockaddr_in*) peerAddr, (sockaddr_in*) &(peer->sockaddr),
			sizeof(sockaddr_in));
	peer->port = peerAddr->sin_port;
	/*cout << "Peer: " << peer->sockaddr.sin_port << ":"
	 << inet_ntoa(peer->sockaddr.sin_addr) << endl;*/
	calc_id(inet_ntoa(peer->sockaddr.sin_addr), peer->port, id);
	memcpy(peer->id, id, ID_SIZE);

	free(id);
	return 1;
}
/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer) {
	int i;
//cout<<"Inside print_peer"<<endl;
	if (peer) {
		printf("peer: %s:%u ", inet_ntoa(peer->sockaddr.sin_addr), peer->port);
		printf("id: ");
		for (i = 0; i < ID_SIZE; i++) {
			printf("%02x", peer->id[i]);
		}
		printf("\n");
	}
}

//Function to hold handshake message.
int createHndshkMsg(char *handshakemsg, sockaddr_in clientAddr,
		char *infohash) {
	//cout<<"Inside function"<<endl;
	handshakemsg[0] = '\0';
	unsigned char prt1 = (unsigned char) 19;
	char prt2[] = "BitTorrent Protocol00000000";
	unsigned short port = clientAddr.sin_port;
	char *ip = inet_ntoa(clientAddr.sin_addr);
	char *id;

	id = (char*) malloc((SHA_DIGEST_LENGTH + 1) * sizeof(char));
	calc_id(ip, port, id);
	id[SHA_DIGEST_LENGTH] = '\0';
	memcpy(handshakemsg, &prt1, 1);
	handshakemsg[1] = '\0';
	//cout<<handshakemsg<<":"<<strlen(handshakemsg)<<endl;
	strcat(handshakemsg, prt2);
	strcat(handshakemsg, infohash);
	//cout<<handshakemsg<<":"<<strlen(handshakemsg)<<endl;
	strcat(handshakemsg, id);
	handshakemsg[68] = '\0';
	//cout<<handshakemsg<<":"<<strlen(handshakemsg)<<endl;
	if (strlen(handshakemsg) == 68) {
		free(id);
		return 1;
	} else {
		free(id);
		return -1;
	}
}

//Function to set messages based on the message type.
void setMsg(bt_msg *bt_msg, int type, bt_info_t bt_info) {
	int noOfPieces;
	unsigned int tsum = 0;
	switch (type) {
	case BT_UNCHOKE:
		bt_msg->bt_type = 1;
		bt_msg->length = 1;
		break;

	case BT_BITFILED:
		bt_msg->bt_type = BT_BITFILED;
		noOfPieces = bt_info.num_pieces;
		if (noOfPieces < 8) {
			bt_msg->payload.bitfield.size = 1;
		} else if (noOfPieces % 8 == 0) {
			bt_msg->payload.bitfield.size = noOfPieces / 8;
		}

		else if (bt_info.num_pieces > 8) {
			bt_msg->payload.bitfield.size = (noOfPieces / 8) + 1;
		}

		for (int i = 0; i < bt_msg->payload.bitfield.size; i++) {
			tsum = 0;
			for (int j = 0; j < (noOfPieces - (8 * i)) && j < 8; j++) {
				tsum = tsum + pow(2, (8 - (j + 1)));
			}
			bt_msg->payload.bitfield.bitfield[i] = tsum;
			//cout << (unsigned int) bt_msg->payload.bitfield.bitfield[i] << endl;
		}
		bt_msg->length = 1 + bt_msg->payload.bitfield.size;
		break;

	case BT_INTERSTED:
		bt_msg->bt_type = BT_INTERSTED;
		bt_msg->length = 1;
		break;

	}

}

//Function to set messages based on the message type.
void setMsg(bt_msg *bt_msg, int type, int index, int offset) {
	switch (type) {
	case BT_REQUEST:
		bt_msg->bt_type = BT_REQUEST;
		bt_msg->payload.request.index = index;
		bt_msg->payload.request.begin = offset;
		bt_msg->payload.request.length = 256;
		break;
	}
}

//Function to set messages based on the message type.
void setMsg(bt_msg *bt_msg, int type, bt_piece_t piece, int* length) {

	switch (type) {
	case BT_PIECE:
		bt_msg->bt_type = BT_PIECE;
		bt_msg->payload.piece.index = piece.index;
		bt_msg->payload.piece.begin = piece.begin;
		bt_msg->payload.piece.length = *length;
		memcpy(bt_msg->payload.piece.piece, piece.piece, *length);
		break;
	}
}

//Function to set messages based on the message type.
void setMsg(bt_msg *bt_msg, int type, int have) {

	switch (type) {

	case BT_HAVE:
		bt_msg->bt_type = BT_HAVE;
		bt_msg->length = 1;
		bt_msg->payload.have = have;
		break;
	}
}

//Method to parse message and set values in the peer array.
void parsMsg(bt_msg bt_msg, peer_t *peer) {
	int trackFlag = 0;
	int k;
	//cout << "Type: " << bt_msg.bt_type << endl;
	switch (bt_msg.bt_type) {
	case BT_UNCHOKE:
		peer->choked = 0;
		break;

	case BT_BITFILED:
		//cout << "Length: " << bt_msg.length << endl;
		//cout << "Bitfield Size: " << bt_msg.payload.bitfield.size << endl;
		//cout << "Bitfield: ";

		for (int i = 0; i < bt_msg.payload.bitfield.size * 8; i++) {
			if (peer->trackPieces[i] == 1) {
				trackFlag = 1;
				break;
			}
		}
		if (!trackFlag) {
			k = 0;
			for (int i = 0; i < bt_msg.payload.bitfield.size; i++) {
				for (int j = 7; j >= 0; j--, k++) {
					peer->trackPieces[k] = ((bt_msg.payload.bitfield.bitfield[i]
							>> j) & 1);
					//cout << (unsigned int) peer->trackPieces[k];
				}
			}
		}
		cout << endl;
		break;

	case BT_INTERSTED:
		peer->interested = 1;
		break;

	case BT_REQUEST:
		break;

	case BT_HAVE:

		break;
	}
}

//Method to send messages to peer.
int send_to_peer(int socket, bt_msg_t * msg) {
	if ((send(socket, (const void*) msg, sizeof(bt_msg_t), 0) < 0)) {
		cout << "Err while sending" << endl;
		perror("Error: ");
		return -1;
	} else {

	}
	return 0;
}

//Method to read messages from peer.
int read_from_peer(int socket, bt_msg_t *msg) {
	char* buf;
	buf = (char*) malloc(sizeof(bt_msg_t) * sizeof(char));
	int totalBytesReceived = 0;
	int bytesRcvd = 0;

	do {
		if ((bytesRcvd = recv(socket, buf, sizeof(bt_msg_t), 0) > 0)) {
			totalBytesReceived += bytesRcvd;
			memcpy(msg, buf, sizeof(bt_msg_t));
		}
	} while (!(msg->bt_type >= 0 && msg->bt_type <= 8));

	free(buf);

	if (bytesRcvd < 0) {
		return -1;
	} else if (bytesRcvd == 0) {
		return 0;
	} else
		return totalBytesReceived;

}

//Method to load pieces into the message structure.
int load_piece(bt_args_t * bt_args, bt_msg *bt_msg, bt_piece_t *piece,
		int *length) {

	int offset = 0;

	memset(piece->piece, 0, 256);
	piece->begin = bt_msg->payload.request.begin;
	piece->index = bt_msg->payload.request.index;
	offset = (bt_args->bt_info->piece_length * bt_msg->payload.request.index)
			+ bt_msg->payload.request.begin;
	ifstream ifile(bt_args->bt_info->name, std::ifstream::binary);
	if (ifile) {

		ifile.seekg(offset, ifile.beg);

		ifile.read(piece->piece, bt_msg->payload.request.length);
		ifile.close();

		*length = ifile.gcount();

	} else {

		cout << "invalid file" << endl;
		return -1;
	}
	return 0;
}

//Method to save pieces in a file.
int save_piece(bt_args_t * bt_args, bt_msg *bt_msg, SHA_CTX *c,
		ofstream& ofile) {

	int offset = 0;

	if (ofile) {
		offset = (bt_args->bt_info->piece_length * bt_msg->payload.piece.index)
				+ bt_msg->payload.piece.begin;
		SHA1_Update(c, (const void*) bt_msg->payload.piece.piece,
				bt_msg->payload.piece.length);
		ofile.seekp(offset);

		ofile.write(bt_msg->payload.piece.piece, bt_msg->payload.piece.length);

	}

	else {

		cout << "invalid file" << endl;
		return -1;
	}
	return 0;
}
