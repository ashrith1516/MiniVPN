#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <stdlib.h>
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

int  setupTCPServer();                   // Defined in Listing 19.10
void processRequest(SSL* ssl, int sockfd, int tunfd); // Defined in Listing 19.12

struct sockaddr_in peerAddr;
int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_TUN = Create a TUN interface,	IFF_NO_PI = Do not display packet information

	tunfd = open("/dev/net/tun", O_RDWR); //Creating a file descriptor associated with the TUN interface
	ioctl(tunfd, TUNSETIFF, &ifr); //Configuring the TUN interface with flags and associating it with the file descriptor

	return tunfd;
}

//Stuff to do when a packet is received at the TUN interface
void tunSelected(int tunfd, int sockfd, SSL *ssl) {
	int  len;
	char buff[BUFF_SIZE];

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE); //Read unencrypted data and encrypt to be sent across tunnel
	buff[len] = '\0';
	SSL_write(ssl, buff, len); //Encrypt data and send it to client
}

//Stuff to do when a packet is received at the TCP socket interface
void socketSelected(int tunfd, int sockfd, SSL *ssl) {
	int  len;
	char buff[BUFF_SIZE];

	bzero(buff, BUFF_SIZE);
	len = SSL_read (ssl, buff, BUFF_SIZE); //Read encrypted data received from tunnel and decrypt it
	buff[len] = '\0';
	//Packet received at the socket interface is encrypted and needs to be decrypted or vice versa. Hence we write to the TUN interface
	write(tunfd, buff, len); //Send unencrypted data to appropriate host

}

int main(){

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;
  
  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./vpnserver-crt.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./vpnserver.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new(ctx);
  int tunfd,sockfd;
  tunfd = createTunDevice();
  
  //Bringing up the TUN interface and setting up routing tables
  system("/home/seed/VPN/tunserver.sh");
  
  struct sockaddr_in sa_client;
  int client_len = sizeof(sa_client);
  int listen_sock = setupTCPServer();

  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if (fork() == 0) { // The child process
       close (listen_sock);

       SSL_set_fd (ssl, sock);
       int err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");

       processRequest(ssl, sock, tunfd);
       close(sock);
       return 0;
    } else { // The parent process
        close(sock);
    }
  }
  
}


int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void processRequest(SSL* ssl, int sockfd, int tunfd)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
	
	//Authentication
    printf("%s wants to connect...\n",buf);
    struct spwd *pw;
    char *epasswd;
	//Gets local user account password for the user. NULL indicates user does not exist
    pw = getspnam(buf);
	if (pw == NULL) {
	 printf("Closing user connection due to insufficient privileges\n");
	 SSL_write(ssl, "0", 1);
	 return;
	}
	//0 indicates failure and 1 indicates success to the client
    SSL_write(ssl, "1", 1);
    len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
	//Check for wrong password entered
    epasswd = crypt(buf, pw->sp_pwdp);

    if (strcmp(epasswd, pw->sp_pwdp)) {
	printf("Wrong password! Closing user connection\n");
	SSL_write(ssl, "0", 1);
	return;
	}
    printf("User authenticated\n");
    SSL_write(ssl, "1", 1);
    
    while (1) {
	  fd_set readFDSet;

	  FD_ZERO(&readFDSet);
	  FD_SET(sockfd, &readFDSet);
	  FD_SET(tunfd, &readFDSet);
	  select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

	  if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd,ssl);
	  if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl);
  }
    SSL_shutdown(ssl);  SSL_free(ssl);
}
