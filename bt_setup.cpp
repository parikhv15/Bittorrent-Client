#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "Socket.h"
#include "bt_setup.h"
#include "bt_lib.h"
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>

using namespace std;

/**
 * usage(FILE * file) -> void
 *
 * print the usage of this program to the file stream file
 *
 **/

void usage(FILE * file){
  if(file == NULL){
    file = stdout;
  }

  fprintf(file,
          "bt-client [OPTIONS] file.torrent\n"
          "  -h            \t Print this help screen\n"
          "  -b ip         \t Bind to this ip for incoming connections, ports\n"
          "                \t are selected automatically\n"
          "  -s save_file  \t Save the torrent in directory save_dir (dflt: .)\n"
          "  -l log_file   \t Save logs to log_filw (dflt: bt-client.log)\n"
          "  -p ip:port    \t Instead of contacing the tracker for a peer list,\n"
          "                \t use this peer instead, ip:port (ip or hostname)\n"
          "                \t (include multiple -p for more than 1 peer)\n"
          "  -I id         \t Set the node identifier to id (dflt: random)\n"
          "  -v            \t verbose, print additional verbose info\n");
}

/**
 * __parse_peer(peer_t * peer, char peer_st) -> void
 *
 * parse a peer string, peer_st and store the parsed result in peer
 *
 * ERRORS: Will exit on various errors
 **/

void __parse_peer(peer_t * peer, char * peer_st){
	//cout<<"inside __parse_peer"<<endl;
  char * parse_str;
  char * word;
  unsigned short port;
  char * ip;
  char id[21];
  memset(id,0,21);
  char sep[] = ":";
  int i=0;

  //need to copy becaus strtok mangels things
  parse_str = (char*)malloc(strlen(peer_st)+1);
  strncpy(parse_str, peer_st, strlen(peer_st)+1);

  //only can have 2 tokens max, but may have less
  for(word = strtok(parse_str, sep), i=0;
      (word && i < 3);
      word = strtok(NULL,sep), i++){

    printf("%d:%s\n",i,word);
    switch(i){
    case 0://id
      ip = word;
      break;
    case 1://ip
      port = atoi(word);
      break;
    default:
      break;
    }

  }

  if(i < 2){
    fprintf(stderr,"ERROR: Parsing Peer: Not enough values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }

  if(word){
    fprintf(stderr, "ERROR: Parsing Peer: Too many values in '%s'\n",peer_st);
    usage(stderr);
    exit(1);
  }


  //calculate the id, value placed in id
  calc_id(ip,port,id);

  //build the object we need
  init_peer(peer, id, ip, port);
  //free extra memory
  free(parse_str);

  return;
}

/**
 * pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
 *
 * parse the command line arguments to bt_client using getopt and
 * store the result in bt_args.
 *
 * ERRORS: Will exit on various errors
 *
 **/
void parse_args(bt_args_t * bt_args, int argc,  char * argv[]){

	if(!(argc>3)){

		usage(stderr);
		exit(1);
	}
  int ch; //ch for each flag
  int n_peers = 0;
  int i=0;
  int listenFlag=0;
  /* set the default args */
  bt_args->verbose=0; //no verbosity

  //null save_file, log_file and torrent_file
  memset(bt_args->save_file,0x00,FILE_NAME_MAX);
  memset(bt_args->torrent_file,0x00,FILE_NAME_MAX);
  memset(bt_args->log_file,0x00,FILE_NAME_MAX);

  //null out file pointers
  bt_args->f_save = NULL;

  //null bt_info pointer, should be set once torrent file is read
  bt_args->bt_info = NULL;

  //default lag file
  strncpy(bt_args->log_file,"bt-client.log",FILE_NAME_MAX);

  for ( i= 0;  i< MAX_CONNECTIONS; i++) {
	  bt_args->listen[i]=0;
}

  for(i=0;i<MAX_CONNECTIONS;i++){
    bt_args->peers[i] = NULL; //initially NULL
  }

  bt_args->id = 0;

  while ((ch = getopt(argc, argv, "hp:s:l:vI:b:")) != -1) {
    switch (ch) {
    case 'h': //help
      usage(stdout);
      exit(0);
      break;
    case 'v': //verbose
      bt_args->verbose = 1;
      break;
    case 's': //save file
      strncpy(bt_args->save_file,optarg,FILE_NAME_MAX);
      break;
    case 'l': //log file
      strncpy(bt_args->log_file,optarg,FILE_NAME_MAX);
      break;

    case 'b':
    	if(!(argc>=4 && argc<=7)){

    		usage(stderr);
    		exit(1);
    	}
    	bt_args->listen[listenFlag]=1;
    	bt_args->peers[listenFlag] = (peer_t*)malloc(sizeof(peer_t));
    	__parse_peer(bt_args->peers[listenFlag], optarg);
    	listenFlag++;
    	//cout<<listenFlag<<endl;
    break;
    case 'p': //peer
    	if(!(argc>=6)){

    	    		usage(stderr);
    	    		exit(1);
    	    	}
      n_peers++;
      //check if we are going to overflow
      if(n_peers > MAX_CONNECTIONS){
        fprintf(stderr,"ERROR: Can only support %d initial peers",MAX_CONNECTIONS);
        usage(stderr);
        exit(1);
      }
      bt_args->peers[0] = (peer_t*)malloc(sizeof(peer_t));
      bt_args->peers[n_peers] = (peer_t*)malloc(sizeof(peer_t));


      __parse_peer(bt_args->peers[n_peers], optarg);
      break;
    case 'I':
      bt_args->id = atoi(optarg);
      break;
    default:
      fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
      usage(stdout);
      exit(1);
    }
  }


  argc -= optind;
  argv += optind;

  if(argc == 0){
    fprintf(stderr,"ERROR: Require torrent file\n");
    usage(stderr);
    exit(1);
  }
  else if(argc!=1){

	  usage(stderr);
	  exit(1);
  }

  //copy torrent file over
  strncpy(bt_args->torrent_file,argv[0],FILE_NAME_MAX);
//cout<<bt_args->torrent_file<<endl;
  return ;
}

