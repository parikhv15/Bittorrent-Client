//Bittorret Client file - bt_client.cpp
#include <stdio.h>
#include <time.h>
#include <math.h>
#include <sstream>
#include<errno.h>
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
#include <pthread.h>
#include <iomanip>
#define TEMPLEN 1024
#define SHA_DIGEST_LENGTH 20
#define TRUE 1
#define FALSE 0

using namespace std;
void* clientThreadStart(void*);

//condition variable to be used for child first thread to die
pthread_cond_t gCondToWakeUp;
pthread_mutex_t threadMutexCond;
int flagClose = 0;
int numberOfThreadSccs = 0;

//structures to hold arguments for thread arguments.
typedef struct threadArgs {

	int clntSock;
	char infohash[20];
	struct sockaddr_in peerAddr;
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	bt_info_t bt_info;
	bt_piece_t bt_piece;
} thrd_args;

typedef struct seederArgs {

	int servSock;
	char handshakemsg[68];
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	bt_info_t bt_info;
	bt_piece_t bt_piece;
	peer_t peer;
} seed_args;

typedef struct sthreadStartArgs {

	int servSock;
	char infohash[20];
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	bt_info_t bt_info;
	bt_piece_t bt_piece;
	struct sockaddr_in addr;
} start_args;

//Thread method to handle multiple leechers.
void * threadLeecher(void * args) {
	pthread_detach(pthread_self());

	char * handshakemsg;
	char *msg;
	char infohash[21];
	string log_msg;
	stringstream lm;

	struct sockaddr_in peerAddr;
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	bt_info_t bt_info;
	bt_piece_t piece;

	int breakFlag = 0;
	int handshake = 0;
	int loffset = 0;
	int success = 0;
	int /*index = 0,*/p_index = 0, length = 0;

	int clntSock = ((struct threadArgs*) args)->clntSock;

	handshakemsg = (char*) malloc((HNDSHKMSGLEN + 1) * sizeof(char));
	msg = (char*) malloc(256 * sizeof(char));

	memcpy(infohash, ((struct threadArgs*) args)->infohash, 20);
	bcopy(&((struct threadArgs*) args)->bt_args, &bt_args, sizeof(bt_args_t));
	bcopy(&((struct threadArgs*) args)->bt_msg, &bt_msg, sizeof(bt_msg_t));
	bcopy(&((struct threadArgs*) args)->bt_piece, &piece, sizeof(bt_piece_t));
	bcopy(&((struct threadArgs*) args)->bt_info, &bt_info, sizeof(bt_info_t));
	bcopy(&((struct threadArgs*) args)->peerAddr, &peerAddr,
			sizeof(sockaddr_in));

	ofstream log(bt_args.log_file, std::ofstream::out | std::ofstream::app);
	clock_t time_s, time;
	time_s = clock();

	for (int i = 1; i < MAX_CONNECTIONS; i++) {

		if (bt_args.sockets[i] == 0) {
			bt_args.sockets[i] = clntSock;
			bt_args.peers[i] = (peer_t*) malloc(sizeof(peer_t));
			add_peer(bt_args.peers[i], &peerAddr);

			lm.clear();
			lm.str("");
			log_msg.clear();
			time = clock() - time_s;
			lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
					<< "Leecher Connected: " << "Peer: "
					<< inet_ntoa(peerAddr.sin_addr) << ":" << peerAddr.sin_port;
			log_msg = lm.str();
			log << log_msg << endl;
			//--cout << "port::" << bt_args.peers[i]->port << endl;
			break;
		}

	}

	createHndshkMsg(handshakemsg, peerAddr, infohash);
	//cout << handshakemsg << endl;
	Socket sockobj;
	int rcvdBytes = 0;

	if ((rcvdBytes = sockobj.recvMsg(clntSock, msg, 68)) <= 0) {

		if (rcvdBytes == 0) {
			cout << "Client Disconnected" << endl;
		} else {
			perror("recv");
		}
		close(clntSock);
		success = 1;
		pthread_exit(&success);

	} else {
		lm.clear();
		lm.str("");
		log_msg.clear();
		time = clock() - time_s;
		lm << "[" << (float) time / CLOCKS_PER_SEC << "]" << "Handshake Init: "
				<< "Peer: " << inet_ntoa(peerAddr.sin_addr) << ":"
				<< peerAddr.sin_port;
		log_msg = lm.str();
		log << log_msg << endl;
		//cout << rcvdBytes << endl;
		msg[rcvdBytes] = '\0';
		//cout << msg << endl;
	}
	//cout << memcmp(handshakemsg, msg, HNDSHKMSGLEN) << endl;
	if (memcmp(handshakemsg, msg, HNDSHKMSGLEN) == 0) {
		unsigned char *tempId = (unsigned char*) malloc(
				(ID_SIZE + 1) * sizeof(char));
		memcpy(tempId, &bt_args.peers[0]->id, ID_SIZE);
		tempId[20] = '\0';
		if (send(clntSock, (char *) tempId, 20, 0) < 0) {
			cout << "error in send" << endl;
			exit(1);
		} else {

			lm.clear();
			lm.str("");
			log_msg.clear();
			time = clock() - time_s;
			lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
					<< "Handshake Successful: " << "Peer: "
					<< inet_ntoa(peerAddr.sin_addr) << ":" << peerAddr.sin_port;
			log_msg = lm.str();
			log << log_msg << endl;
			free(tempId);
			//cout << "tempId sent" << endl;
			handshake = 1;

		}
	} else {
		cout << "Handshake Failed" << endl;
		close(clntSock);
	}
	if (handshake) {
		cout << "Handshake Successful!!" << endl;
		memset(&bt_msg, 0, sizeof(bt_msg_t));
		setMsg(&bt_msg, BT_BITFILED, bt_info);
		if (send_to_peer(clntSock, &bt_msg) < 0) {
			cout << "Error in Send - Bitfield" << endl;
		}
		lm.clear();
		lm.str("");
		log_msg.clear();
		time = clock() - time_s;
		lm << "[" << (float) time / CLOCKS_PER_SEC << "]" << "Bitfield Send: "
				<< "Peer: " << inet_ntoa(peerAddr.sin_addr) << ":"
				<< peerAddr.sin_port;
		log_msg = lm.str();
		log << log_msg << endl;

		memset(&bt_msg, 0, sizeof(bt_msg_t));
		if (read_from_peer(clntSock, &bt_msg) < 0) {
			cout << "Error in Recv - Interested" << endl;
		} else {
			parsMsg(bt_msg, bt_args.peers[1]);
			lm.clear();
			lm.str("");
			log_msg.clear();
			time = clock() - time_s;
			lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
					<< "Interested Msg From: " << "Peer: "
					<< inet_ntoa(peerAddr.sin_addr) << ":" << peerAddr.sin_port;
			log_msg = lm.str();
			log << log_msg << endl;
		}

		memset(&bt_msg, 0, sizeof(bt_msg_t));
		setMsg(&bt_msg, BT_UNCHOKE, bt_info);
		if (send_to_peer(clntSock, &bt_msg) < 0) {
			cout << "Error in Send - Unchoke" << endl;
		} else {
			bt_args.peers[1]->choked = 0;
			lm.clear();
			lm.str("");
			log_msg.clear();
			time = clock() - time_s;
			lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
					<< "Unchoked Msg To: " << "Peer: "
					<< inet_ntoa(peerAddr.sin_addr) << ":" << peerAddr.sin_port;
			log_msg = lm.str();
			log << log_msg << endl;

		}

		loffset = ((1 - bt_info.num_pieces) * bt_info.piece_length)
				+ bt_info.length;

		if (!bt_args.peers[1]->choked) {
			for (int index = 0; index < bt_info.num_pieces; index++) {

				int offset = 0;
				do {

					if (read_from_peer(clntSock, &bt_msg) > 0) {

						lm.clear();
						lm.str("");
						log_msg.clear();
						time = clock() - time_s;
						lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
								<< "Request Msg From: " << "Peer: "
								<< inet_ntoa(peerAddr.sin_addr) << ":"
								<< peerAddr.sin_port << "Piece: "
								<< bt_msg.payload.request.index << "Offset: "
								<< bt_msg.payload.request.begin << "Length: "
								<< bt_msg.payload.request.length;
						log_msg = lm.str();
						log << log_msg << endl;
						p_index = bt_msg.payload.request.index;

						if (load_piece(&bt_args, &bt_msg, &piece, &length)
								< 0) {
							cout << "File Does Not Exists" << endl;
							close(clntSock);
							success = 1;
							pthread_exit(&success);
						}
						memset(&bt_msg, 0, sizeof(bt_msg_t));
						setMsg(&bt_msg, BT_PIECE, piece, &length);
						if (send_to_peer(clntSock, &bt_msg) < 0) {
							cout << "Error in sending piece" << endl;
						}
						lm.clear();
						lm.str("");
						log_msg.clear();
						time = clock() - time_s;
						lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
								<< "Piece Msg To: " << "Peer: "
								<< inet_ntoa(peerAddr.sin_addr) << ":"
								<< peerAddr.sin_port << "Piece: "
								<< bt_msg.payload.piece.index << "Offset: "
								<< bt_msg.payload.piece.begin << "Length: "
								<< bt_msg.payload.piece.length;
						log_msg = lm.str();
						log << log_msg << endl;
					} else {
						breakFlag = 1;
						break;
					}
					offset += 256;
				} while (
						!(p_index == bt_info.num_pieces - 1) ?
								(offset < bt_info.piece_length) :
								(offset < loffset));
				if (breakFlag == 1) {
					break;
				}
				//cout << p_index << "::" << offset << endl;
				memset(&bt_msg, 0, sizeof(bt_msg_t));
				if (read_from_peer(clntSock, &bt_msg) > 0) {
					parsMsg(bt_msg, bt_args.peers[1]);
					lm.clear();
					lm.str("");
					log_msg.clear();
					time = clock() - time_s;
					lm << "[" << (float) time / CLOCKS_PER_SEC << "]"
							<< "Have Msg From: " << "Peer: "
							<< inet_ntoa(peerAddr.sin_addr) << ":"
							<< peerAddr.sin_port << "Piece: "
							<< bt_msg.payload.have;
					log_msg = lm.str();
					log << log_msg << endl;
				}

			}
		}

	}
	log.close();
	handshake = 0;
	close(clntSock);
	free(handshakemsg);
	free(msg);
	free(args); // Deallocate memory for argument
	/*for (int i = 0; i < MAX_CONNECTIONS; i++) {
	 if (bt_args.peers[i] != NULL) {
	 free(bt_args.peers[i]);
	 }
	 }*/
	return NULL;
}

//Thread method to handle seeders.

void * threadSeeder(void * args) {
	//pthread_detach(pthread_self());
	//cout << "\n starting thread : thread id=" << pthread_self() << endl;
	int success = 0;
	//pthread_detach(pthread_self());
	Socket sockobj;
	bt_args_t bt_args;
	bt_msg_t bt;
	bt_piece_t piece;
	bt_info_t bt_info;
	peer_t *peer;

	peer = (peer_t*) malloc(sizeof(peer_t) * sizeof(char));

	int have = 0;
	int pieceFlag = 0;

	string fname;

	char handshakemsg[68];
	char *msg;
	unsigned char* hash;

	msg = (char*) malloc(256 * sizeof(char));
	hash = (unsigned char*) malloc(sizeof(SHA_DIGEST_LENGTH) * sizeof(char));

	SHA_CTX c;

	float percent = 0.0;

	int loffset = 0, p_index;
	int handshake = 0;
	int servSock = ((struct seederArgs*) args)->servSock;

	memcpy(handshakemsg, ((struct seederArgs*) args)->handshakemsg, 68);
	bcopy(&((struct seederArgs*) args)->bt_args, &bt_args, sizeof(bt_args_t));
	bcopy(&((struct seederArgs*) args)->bt_msg, &bt, sizeof(bt_msg_t));
	bcopy(&((struct seederArgs*) args)->bt_piece, &piece, sizeof(bt_piece_t));
	bcopy(&((struct seederArgs*) args)->bt_info, &bt_info, sizeof(bt_info_t));
	bcopy(&((struct seederArgs*) args)->peer, peer, sizeof(peer_t));

	//cout << "Message being Sent" << endl;
	if (sockobj.sendMsg(servSock, handshakemsg) < 0) {
		cout << "error in send-handshake" << endl;

		pthread_mutex_lock(&threadMutexCond);
		flagClose = 1;
		pthread_cond_broadcast(&gCondToWakeUp);
		pthread_mutex_unlock(&threadMutexCond);

		success = 1;
		pthread_exit(&success);
	} else {
		//cout << "msg sent" << endl;
		int rcvd = 0;
		if ((rcvd = sockobj.recvMsg(servSock, msg, 20)) > 0) {
			unsigned char *tempId = (unsigned char*) malloc(
					(ID_SIZE + 1) * sizeof(char));
			memcpy(tempId, &peer->id, ID_SIZE);
			tempId[ID_SIZE] = '\0';
			msg[ID_SIZE] = '\0';

			if (memcmp(tempId, (unsigned char*) msg, 20) == 0) {
				cout << "Handshake Successful!!" << endl;
				handshake = 1;
			} else {
				cout << "handshake failed" << endl;
				close(servSock);
				pthread_mutex_lock(&threadMutexCond);
				flagClose = 1;
				pthread_cond_broadcast(&gCondToWakeUp);
				pthread_mutex_unlock(&threadMutexCond);
				success = 1;
				pthread_exit(&success);
				exit(1);
			}
		} else {
			if (rcvd == 0) {

				cout << "Seeder Disconnected" << endl;
				exit(1);

			} else {
				cout << "Err in rcv-handshake" << endl;
				close(servSock);
				exit(1);
			}

			pthread_mutex_lock(&threadMutexCond);
			flagClose = 1;
			pthread_cond_broadcast(&gCondToWakeUp);
			pthread_mutex_unlock(&threadMutexCond);

			success = 1;
			pthread_exit(&success);
		}
		if (handshake) {
			memset(&bt, 0, sizeof(bt_msg_t));
			if (read_from_peer(servSock, &bt) > 0) {
				//cout << "BF" << endl;
				parsMsg(bt, bt_args.peers[0]);
				//--cout << "Msg rcvd" << endl;
				memset(&bt, 0, sizeof(bt_msg_t));
				setMsg(&bt, BT_INTERSTED, bt_info);
				if (send_to_peer(servSock, &bt) < 0) {
					cout << "Error in Send - Interested" << endl;
				} else {
					memset(&bt, 0, sizeof(bt_msg_t));
					if (read_from_peer(servSock, &bt) > 0) {
						parsMsg(bt, bt_args.peers[0]);
						//cout<<"Msg rcvd"<<endl;
					}
				}
			} else {
				cout << "Error in Recv - Bitfield" << endl;
				close(servSock);
				pthread_mutex_lock(&threadMutexCond);
				flagClose = 1;
				pthread_cond_broadcast(&gCondToWakeUp);
				pthread_mutex_unlock(&threadMutexCond);

				success = 1;
				pthread_exit(&success);
			}
		}
		if (!bt_args.peers[0]->choked) {

			//fname = std::string("Downloads/") + bt_info.name;
			//ofstream ofile((char*) fname.c_str(),std::ofstream::out | std::ofstream::binary);
			ofstream ofile(bt_args.save_file,
					std::ofstream::out | std::ofstream::binary);
			loffset = ((1 - bt_info.num_pieces) * bt_info.piece_length)
					+ bt_info.length;
			bt_args.peers[0]->totalFile = 0.0;
			while (pieceFlag != bt_info.num_pieces) {

				p_index = rand() % bt_info.num_pieces;
				if (bt_args.peers[0]->trackPieces[p_index] == (char) 0) {
					continue;
				}
				int offset = 0;

				SHA1_Init(&c);

				while (!(p_index == bt_info.num_pieces - 1) ?
						(offset < bt_info.piece_length) : (offset < loffset)) {
					setMsg(&bt, BT_REQUEST, p_index, offset);
					if (send_to_peer(servSock, &bt) < 0) {
						cout << "Error in Request: " << p_index << "::"
								<< offset << endl;
					} else {
						memset(&bt, 0, sizeof(bt));

						if (read_from_peer(servSock, &bt) < 0) {
							cout << "Error in Recv(piece)" << endl;
						} else {
							if (save_piece(&bt_args, &bt, &c, ofile) < 0) {
								cout << "File Does Not Exists" << endl;
								close(servSock);
								pthread_mutex_lock(&threadMutexCond);
								flagClose = 1;
								pthread_cond_broadcast(&gCondToWakeUp);
								pthread_mutex_unlock(&threadMutexCond);

								success = 1;
								pthread_exit(&success);
							}
						}
					}

					bt_args.peers[0]->totalFile += bt.payload.piece.length;
					percent = (bt_args.peers[0]->totalFile
							/ (float) bt_args.bt_info->length) * 100.00;
					percent = roundf(percent * 100) / 100;
					if (percent > 100)
						percent = roundf(100);
					offset += 256;
					cout << "\rConnected to:\t"
							<< inet_ntoa(peer->sockaddr.sin_addr)
							<< "  Completed: " << percent << "%";
				}

				SHA1_Final(hash, &c);
				bt_args.peers[0]->trackPieces[p_index] = (char) 0;

				if ((memcmp(hash, bt_args.bt_info->piece_hashes[p_index],
				SHA_DIGEST_LENGTH) != 0)) {
					bt_args.peers[0]->trackPieces[p_index] = (char) 1;
					if (p_index == bt_info.num_pieces - 1) {
						ofile.seekp(
								((bt_info.num_pieces - 1) * bt_info.piece_length));
						ofile.write(" ", loffset);
					} else {
						ofile.seekp(
								((bt_info.num_pieces - 1) * bt_info.piece_length));
						ofile.write(" ", bt_info.piece_length);
					}

				}

				//cout << "Track: " << (int)bt_args.peers[0]->trackPieces[p_index] << endl;
				bt_args.peers[0]->trackPieces[p_index] = (char) 0;
				pieceFlag = 0;
				for (int k = 0; k < bt_info.num_pieces; k++) {
					if (bt_args.peers[0]->trackPieces[k] == (char) 0) {
						//cout << (unsigned int)bt_args.peers[0]->trackPieces[k] << endl;
						pieceFlag++;
					}
					//cout << pieceFlag << endl;
				}
				have = bt.payload.piece.index;
				memset(&bt, 0, sizeof(bt_msg_t));
				setMsg(&bt, BT_HAVE, have);
				if (send_to_peer(servSock, &bt) < 0) {
					cout << "Error in Send - Have" << endl;
				}
			}
			ofile.flush();
			ofile.close();
		}
	}
	//reached here means success
	pthread_mutex_lock(&threadMutexCond);
	numberOfThreadSccs++;
	//cout << "thread-id exiting : " << pthread_self() << " connection number : "
	//<< numberOfThreadSccs << endl;
	pthread_cond_broadcast(&gCondToWakeUp);
	pthread_mutex_unlock(&threadMutexCond);
	success = 1;
	pthread_exit(&success);

	free(peer);
	free(hash);
	free(args);
	free(msg);
}

int main(int argc, char * argv[]) {

	int end_s = FALSE;
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	int i = 0;
	char *infohash;
	string fname;
	Socket sockobj;
	bt_info_t bt_info;
	parse_args(&bt_args, argc, argv);
	int clntSock = 0;
	struct sockaddr_in addr;
	struct sockaddr_in peerAddr;
	unsigned int peerAddrLength = sizeof(peerAddr);

	infohash = (char*) malloc((SHA_DIGEST_LENGTH + 1) * sizeof(char));

	parse_bt_info(&bt_info, bt_args, infohash);
	infohash[SHA_DIGEST_LENGTH] = '\0';

	bt_args.bt_info = (bt_info_t*) malloc(sizeof(bt_info) * sizeof(char));
	memcpy(bt_args.bt_info, &bt_info, sizeof(bt_info));

	if (bt_args.verbose) {
		printf("Args:\n");
		printf("verbose: %d\n", bt_args.verbose);
		printf("save_file: %s\n", bt_args.save_file);
		printf("log_file: %s\n", bt_args.log_file);
		printf("torrent_file: %s\n", bt_args.torrent_file);
		printf("Name: %s \n", bt_info.name);
		printf("Length: %d \n", bt_info.length);
		printf("Piece Length: %d \n", bt_info.piece_length);
		printf("Number of Pieces: %d \n", bt_info.num_pieces);

		for (i = 1; i < MAX_CONNECTIONS; i++) {
			if (bt_args.peers[i] != NULL)
				//	cout << "i:" << i << endl;
				print_peer(bt_args.peers[i]);
		}

	}

//read and parse the torrent file here

	if (bt_args.verbose) {
		cout << "File Name: " << bt_args.bt_info->name << endl;
		// print out the torrent file arguments here
	}

	for (int i = 0; i < MAX_CONNECTIONS; i++) {
		bt_args.sockets[i] = 0;
	}

	if (bt_args.listen[0] == 1) {
		bt_args.sockets[0] = sockobj.createSocket();
		bzero(&(addr), sizeof(addr));
		if (sockobj.bindToPort(bt_args.peers[0], bt_args.sockets[0]) < 0) {
			fprintf(stderr,
					"ERROR: The port is busy. Please try connecting to another port.\n");
			exit(1);
		}
		if (sockobj.listenForConnections(bt_args.sockets[0]) < 0) {
			fprintf(stderr,
					"ERROR: Some error occurred while listening to connections.\n");
			exit(1);
		} else {
			cout << "waiting to connect.." << endl;

		}
		int opt = 1;
		if (setsockopt(bt_args.sockets[0], SOL_SOCKET, SO_REUSEADDR,
				(char *) &opt, sizeof(opt)) < 0) {
			perror("setsockopt");
			exit(EXIT_FAILURE);
		}

		do {
			bzero(&(peerAddr), sizeof(peerAddr));
			if ((clntSock = sockobj.acceptConnections(bt_args.sockets[0],
					&peerAddr, &peerAddrLength)) < 0) {
				if (errno != EWOULDBLOCK) {
					perror("  accept() failed");
					end_s = TRUE;
				}
				fprintf(stderr,
						"ERROR: Some error occurred while connecting to the client.\n");
				exit(1);
			} else {

				cout << "Connected to: " << peerAddr.sin_port << ":"
						<< inet_ntoa(peerAddr.sin_addr) << endl;
				thrd_args *threadArgs1 = (thrd_args*) malloc(sizeof(thrd_args));

				threadArgs1->clntSock = clntSock;
				memcpy(threadArgs1->infohash, infohash, SHA_DIGEST_LENGTH);
				bcopy(&bt_args, &threadArgs1->bt_args, sizeof(bt_args_t));
				bcopy(&bt_msg, &threadArgs1->bt_msg, sizeof(bt_msg_t));
				bcopy(&bt_info, &threadArgs1->bt_info, sizeof(bt_info_t));
				bcopy(&bt_info, &threadArgs1->bt_piece, sizeof(bt_piece_t));
				bcopy(&peerAddr, &threadArgs1->peerAddr, sizeof(peerAddr));
				pthread_t threadId;

				int returnval = pthread_create(&threadId, NULL, threadLeecher,
						threadArgs1);

				if (returnval != 0) {
					printf("with thread %lu\n", (unsigned long int) threadId);
				}
				//free(threadArgs1);
			}

		} while (end_s == FALSE);
	} else {

		start_args *sthreadStartArgs = (start_args*) malloc(sizeof(start_args));

		sthreadStartArgs->servSock = bt_args.sockets[i];
		memcpy(sthreadStartArgs->infohash, infohash, 20);
		bcopy(&bt_args, &sthreadStartArgs->bt_args, sizeof(bt_args_t));
		bcopy(&bt_msg, &sthreadStartArgs->bt_msg, sizeof(bt_msg_t));
		bcopy(&bt_info, &sthreadStartArgs->bt_info, sizeof(bt_info_t));
		bcopy(&bt_info, &sthreadStartArgs->bt_piece, sizeof(bt_piece_t));

		pthread_t threadId_s;

		int returnval = 0;
		pthread_create(&threadId_s, NULL, clientThreadStart, sthreadStartArgs);
		int* returnValPtr = &returnval;
		pthread_join(threadId_s, (void**) &returnValPtr);
		if (*returnValPtr != 0) {
			printf("with thread %lu\n", (unsigned long int) threadId_s);
		}
		//free(sthreadStartArgs);
	}

	for (int i = 0; i < bt_info.num_pieces; i++)
		free(bt_info.piece_hashes[i]);
	free(bt_info.piece_hashes);

	free(infohash);
	return 0;
}

//Method to create child threads.
void* clientThreadStart(void* args) {

	pthread_cond_init(&gCondToWakeUp, NULL);
	pthread_mutex_init(&threadMutexCond, NULL);
	pthread_detach(pthread_self());

	sockaddr_in addr;
	Socket sockobj;
	bt_args_t bt_args;
	bt_msg_t bt_msg;
	bt_piece_t piece;
	bt_info_t bt_info;
	//peer_t *peer = (peer_t*) malloc(sizeof(peer_t) * sizeof(char));

	char * handshakemsg;

	handshakemsg = (char*) malloc((HNDSHKMSGLEN + 1) * sizeof(char));

	//int have = 0;
	//int pieceFlag = 0;

	string fname;

	char infohash[20];

	memcpy(infohash, ((struct threadArgs*) args)->infohash, 20);
	bcopy(&((struct sthreadStartArgs*) args)->bt_args, &bt_args,
			sizeof(bt_args_t));
	bcopy(&((struct sthreadStartArgs*) args)->bt_msg, &bt_msg,
			sizeof(bt_msg_t));
	bcopy(&((struct sthreadStartArgs*) args)->bt_piece, &piece,
			sizeof(bt_piece_t));
	bcopy(&((struct sthreadStartArgs*) args)->bt_info, &bt_info,
			sizeof(bt_info_t));

	unsigned int addrLength = sizeof(addr);

	pthread_t threadIds[MAX_CONNECTIONS];
	int numberOfIndex = 0;
	int numberOfConn = 0;
	int connErrorFlag = 0;

	for (int i = 1; i < MAX_CONNECTIONS; i++) {
		if (connErrorFlag == MAX_CONNECTIONS) {
			exit(1);
		} else {
			if (bt_args.peers[i] != NULL) {
				numberOfConn += 1;
				bt_args.sockets[i] = sockobj.createSocket();
				//cout << "Sockets: " << bt_args.sockets[i] << endl;
				bzero(&(addr), sizeof(addr));
				if (sockobj.connectToSeeder(bt_args.peers[i],
						bt_args.sockets[i], &addr, &addrLength) < 0) {
					fprintf(stderr,
							"ERROR: Server(s) not running. Connection to server was not established.\n");
					//exit(1);
					connErrorFlag++;
					bt_args.peers[i] = NULL;
					numberOfConn--;
					continue;
				} else {

					cout << "Connected to the server..." << endl;
					createHndshkMsg(handshakemsg, addr, infohash);

				}
				seed_args *seederArgs = (seed_args*) malloc(sizeof(seed_args));

				seederArgs->servSock = bt_args.sockets[i];
				memcpy(seederArgs->handshakemsg, handshakemsg, 68);
				bcopy(&bt_args, &seederArgs->bt_args, sizeof(bt_args_t));
				bcopy(&bt_msg, &seederArgs->bt_msg, sizeof(bt_msg_t));
				bcopy(&bt_info, &seederArgs->bt_info, sizeof(bt_info_t));
				bcopy(&bt_info, &seederArgs->bt_piece, sizeof(bt_piece_t));
				bcopy(bt_args.peers[i], &seederArgs->peer, sizeof(peer_t));
				//pthread_t threadId;

				int returnval = 0;
				pthread_create(&threadIds[numberOfIndex++], NULL, threadSeeder,
						seederArgs);
				int* returnValPtr = &returnval;
				//pthread_join(threadId, (void**) &returnValPtr);
				if (*returnValPtr != 0) {
					printf("with thread %lu\n",
							(unsigned long int) threadIds[numberOfIndex]);
				}

			}

		}
	}
	free(args);
	//this will wait for the other thread to die
	pthread_mutex_lock(&threadMutexCond);

	while (flagClose != 1) {
		//no error so far and still some threads yet to complete
		if (numberOfThreadSccs == numberOfConn) {
			//cout << "all chunks are successfully received. ";
			break;
		}
		pthread_cond_wait(&gCondToWakeUp, &threadMutexCond);
	}
	//there has been an error so kill all other threads
	if (flagClose == 1) {
		cout << "Error has occurred in thread processing.";
		for (int i = 0; i < numberOfIndex; i++) {
			pthread_kill(threadIds[i], SI_ASYNCNL);
		}
	}
	//pthread_cancel(thread[i]);
	pthread_mutex_unlock(&threadMutexCond);
	//flagClose = 0;

	//this thread is dying
	pthread_exit((void*) &flagClose);

}

