#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include "sha1.h"
#include "base64.h"


char *substring(char *string, int position, int length) 
{
   char *pointer;
   int c;
   pointer = (char*)malloc(length+1);
   if (pointer == NULL)
   {
      printf("Unable to allocate memory.\n");
      exit(1);
   }
   for (c = 0 ; c < position -1 ; c++) 
      string++; 
   for (c = 0 ; c < length ; c++)
   {
      *(pointer+c) = *string;      
      string++;   
   }
   *(pointer+c) = '\0';
   return pointer;
}
char* extract_substring(char *string, char *pattern_start,char *pattern_end)
{
	char* pch;
        char* spch;
        pch = strstr(string,pattern_start);
	if (pch==NULL) return NULL;
        spch = strstr(pch,pattern_end);
	if (pch==NULL) return NULL;
        char* s = substring(pch+strlen(pattern_start), 0, spch - pch - strlen(pattern_start)- 1);
        return s;
}

void send_sock_text(int clientSock, char* msg) {
		unsigned int len = strlen(msg);
		unsigned char buffer[1024];
		memset(buffer, 0, sizeof(buffer));
		// 0x80 means final fragment and 0x01 means opecode is text frame
		buffer[0] = 0x01 | 0x80; // opcode
		buffer[1] = len; // payload length
		memcpy(buffer + 2, msg, len);
		write(clientSock, buffer, strlen(buffer));
}

unsigned char* decoded_message(unsigned char* buffer)
{
	if (buffer[0] == 0x81){
		//Is text frame and final message
                int decode_msg_length = buffer[1] & 0x7F;
                //printf("decode_msg_length=%d\n",decode_msg_length);
                unsigned char encoded_key[4];
                encoded_key[0]=buffer[2];
                encoded_key[1]=buffer[3];
                encoded_key[2]=buffer[4];
                encoded_key[3]=buffer[5];
                unsigned char* decoded_msg = (unsigned char*) malloc(decode_msg_length);
                int i;
                for(i=0;i< decode_msg_length ;i++){
                	decoded_msg[i] = (buffer[i+6] ^ encoded_key[i % 4]);
                        //printf("[%c]\n", decoded_msg[i]);
                }
		/*
                if ((decoded_msg[0] == 'a') && (decode_msg_length == 1)){
                	send_sock_text(clientSock,"get a\r\n");
                }
		*/
		return decoded_msg;
	}else {
		return NULL;
	}
}

void handle_message_loop(int clientSock)
{
	unsigned char buffer[1024];
        memset(buffer,0,sizeof(buffer));
        while(1){
        	int byteCount = read(clientSock , buffer, sizeof(buffer));
                if ( byteCount >= 0 ) {
			unsigned char* decoded_msg = decoded_message(buffer);
			if (decoded_msg == NULL){
                                if (buffer[0] == 0x88){
					printf("socket suddenly close\n");
                                        break;
                                }
				//----------------------------------------------------
                                int i;
                                for(i=0;i<(int)strlen(buffer);i++){
                                        //printf("\ni=%d/%d\n",i,(int) strlen(read_buf));
                                        //printf("[%s]\n", read_buf);
                                        printf("0x%02x ",buffer[i]);
                                }
                                printf("\n");
				//----------------------------------------------------
                        }else{
				printf("Get message [%s]\n",decoded_msg);
				char *get_val;
				if ( (get_val = extract_substring(decoded_msg,"connection:", "\n")) != NULL){
					printf("get_val=connection:%s\n",get_val);	
					char*client_msg=(char*)malloc(512);
					strcpy(client_msg,"connection:");
					strcat(client_msg,get_val);
					//strcat(client_msg,"\n");
                			send_sock_text(clientSock,client_msg);
				}else if ( (get_val = extract_substring(decoded_msg,"input:", "\n")) != NULL){
					printf("get_val=input:%s\n",get_val);
					char*client_msg=(char*)malloc(512);
                                        strcpy(client_msg,"input:");
                                        strcat(client_msg,get_val);
                			send_sock_text(clientSock,client_msg);
				}
			}
                }
	}
}

int handle_header(int clientSock, char* buffer)
{
  		char *Sec_WebSocket_Key = extract_substring(buffer ,"Sec-WebSocket-Key: ","\n");
                //printf("[%s]\n",Sec_WebSocket_Key);
                char *magickey = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                char *str = malloc(strlen(Sec_WebSocket_Key)+strlen(magickey));
                memset(str,0,strlen(str));
                strcpy(str,Sec_WebSocket_Key);
                strcat(str,magickey);
                unsigned char *sha1_str;
                sha1_str = getsha1 (str ,strlen(str));
                unsigned char *base64_str;
                size_t len;
                base64_str = base64_encode(sha1_str, strlen(sha1_str), &len);
                //printf("[%s]\n",base64_str);
		char buf[512];
		sprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: chat\r\n\r\n",base64_str);
		/* 
            	printf("----sending to client----\n");
             	printf("%s\n",buf);
             	printf("-------------------------\n");
		*/
		int byteCount = write(clientSock, buf, strlen(buf));
		if (byteCount > 0)
			return 0;
		else 
			return 1;
}

int main( int argc, char const *argv[])
{
    int serverSock ;
    int val = 1;
    struct sockaddr_in serverAddr ;
    struct sockaddr_in clientAddr ;
    socklen_t clientAddrLen = sizeof (clientAddr);
    char buffer [512];

    fprintf(stdout , "%s\n" ,"Start");
    serverSock = socket(AF_INET, SOCK_STREAM , 0 );
    if (serverSock == -1 ) {
        fprintf (stderr, "%s\n" ,"open socket fail");
         return - 1;
    }
    // Make sure the port can be immediately re-used
    if (setsockopt(serverSock, SOL_SOCKET , SO_REUSEADDR, &val , sizeof(val )) < 0 ) {
        fprintf (stderr, "%s\n" ,"can't reuse socket");
        close (serverSock);
         return - 1;
    }
    
    memset(&serverAddr , 0 , sizeof (serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr .s_addr = htonl(INADDR_ANY );
    serverAddr.sin_port = htons(12345);
    if (bind( serverSock, (struct sockaddr *) & serverAddr, sizeof(serverAddr )) != 0 ) {
        fprintf (stderr, "%s\n" ,"can't bind socket");
        close (serverSock);
         return - 1;
    }
    // Listen to socket
    fprintf(stdout , "%s\n" ,"start listen port 12345");
    if (listen( serverSock, 1024) < 0 ) {
         return - 1;
    }

    while(1){
         //accept will wait for message coming
        fprintf (stdout, "%s\n" ,"wait accept");
         int clientSock = accept(serverSock , ( struct sockaddr *) &clientAddr, &clientAddrLen );

         int total_byte_cnt = 0;
         for (;;) {
             int byteCount = read(clientSock , buffer + total_byte_cnt, sizeof(buffer ) - total_byte_cnt - 1);
             if ( byteCount >= 0 ) {
                total_byte_cnt += byteCount;
                buffer [total_byte_cnt] = 0;
		/*
                fprintf (stdout, "[1] %d bytes read\n" , byteCount);
                fprintf (stdout, "%s\n" , "========================" );
                fprintf (stdout, "%s\n" , buffer);
                fprintf (stdout, "%s\n" , "========================" );
		*/
		//
		char *pch = strstr(buffer,"GET / HTTP/1.1");
  		char *Upgrade = extract_substring(buffer ,"Upgrade: ","\n");
  		char *Connection = extract_substring(buffer ,"Connection: ","\n");
		//Sec-WebSocket-Protocol should be "chat"
  		char *Sec_WebSocket_Protocol = extract_substring(buffer ,"Sec-WebSocket-Protocol: ","\n");
		if (pch == NULL) printf("pch is null");
		//printf("[%s]\n", Upgrade);
		//printf("[%s]\n", Connection);
		if ((pch == buffer) && ((strcmp(Upgrade,"websocket") == 0) || (strcmp(Upgrade,"Websocket") == 0)) && ((strcmp(Connection,"Upgrade") == 0) || (strcmp(Connection,"keep-alive, Upgrade") == 0)) ){
			handle_header(clientSock, buffer);
			handle_message_loop(clientSock);
}
                // 
		break;
             } else {
                 //fprintf (stdout, "%s\n" ,"[3] oh no");
                 break;
             }
         }
    }
    fprintf(stdout , "%s\n" ,"Finish");

    return 0;
}


