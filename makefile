
all:
	g++ -g -Wall -o bt bt_client.cpp bt_lib.cpp bt_setup.cpp Socket.cpp -lcrypto -lpthread
