#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <crypt.h>
#define BUFF_SIZE 2000

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stdout); exit(2); }

#define CA_DIR "ca_client"

struct addrinfo hints, *result;

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx); 

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n", 
	   X509_verify_cert_error_string(err));
       printf("Closing connection\n");
       exit(2); 
    }
}

SSL* setupTLSClient(const char* hostname)
{
    // Step 0: OpenSSL library initialization 

   // This step is no longer needed as of version 1.1.0.
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;
   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback); //Verify hostname with the certificate
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }

   ssl = SSL_new (ctx);

   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);
   return ssl;

}

int setupTCPClient(const char* hostname, int port)
{
   struct sockaddr_in server_addr;
   hints.ai_family = AF_INET;

   // Get the IP address from hostname

   int error = getaddrinfo(hostname, NULL, &hints, &result);
   if (error) {
	   fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
	   exit(1);
   }

   struct sockaddr* ip = (struct sockaddr *) result->ai_addr;
   
   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   // Fill in the destination information (IP, port #, and family)
   memset (&server_addr, '\0', sizeof(server_addr));
   //memcpy(&(server_addr.sin_addr), result->ai_addr, result->ai_addrlen);
   server_addr.sin_addr = ((struct sockaddr_in*)ip)->sin_addr; 
   server_addr.sin_port   = htons (port);
   server_addr.sin_family = AF_INET;
   // Connect to the destination
   connect(sockfd, (struct sockaddr*) &server_addr,
           sizeof(server_addr));
   return sockfd;

}

struct sockaddr_in peerAddr;
int createTunDevice() {
	int tunfd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI; //Create interface of type TUN and do not display packet information

	tunfd = open("/dev/net/tun", O_RDWR); //File descriptor for TUN interface
	ioctl(tunfd, TUNSETIFF, &ifr);//Assign flags and create TUN interface
	return tunfd;

}

//Stuff to do when TUN interface receives a packet
void tunSelected(int tunfd, int sockfd, SSL *ssl) {
	
	struct ip* tunsock;
	int  len;
	char buff[BUFF_SIZE];

	//printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE); //Read unencrypted data to encrypt and send across tunnel
	buff[len] = '\0';
	SSL_write(ssl, buff, len);//Encrypt and send the data across the tunnel

}

//Stuff to do when TCP socket interface receives a packet
void socketSelected(int tunfd, int sockfd, SSL *ssl) {

	struct ip* tcpsock;
	int  len;
	char buff[BUFF_SIZE];

	//printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = SSL_read (ssl, buff, BUFF_SIZE);//Read encrypted data from tunnel and decrypt it
	buff[len] = '\0';
	write(tunfd, buff, len);//Send the decrypted data to appropriate host

}

/*----------------Authenticate client--------------------*/
int authenticate(SSL *ssl, char* hostname)
{
   char buf[9000];
   char user[50];
   
   printf("Username : ");
   scanf("%s",user);

   SSL_write(ssl, user, strlen(user));

   int len;
   len = SSL_read (ssl, buf, sizeof(buf) - 1);
	//Server message 0 means a failure in authentication and 1 means success
   if(buf[0] == '0') {
	printf("This user is not allowed to access the application\n");
	exit(0);
   }

   char* pwd = getpass("Password: ");
   SSL_write(ssl, pwd, strlen(pwd));
   len = SSL_read (ssl, buf, sizeof(buf) - 1);

   if(buf[0] == '0') {
	printf("Wrong password!\n");
	exit(0);
   }

}

int main(int argc, char *argv[])
{

   if (argc < 2){
	printf("Usage - ./tlsclient <servername> <port>\n");
	exit(0);
   }   	

   char *hostname = "ashrithchandramouli.com";
   int port = 4433;

   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   printf("Connecting to server %s...\n", hostname);

   int tunfd;
   //Create a TUN interface
   tunfd = createTunDevice();
   //Bring up the TUN interface and assign IP address. Also setup routes required
   system("/home/seed/VPN/tunclient.sh");

   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);
   
   /*----------------Create a TCP connection ---------------*/
   int sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl);
   CHK_SSL(err);
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));
   /*----------------Authenticate client ---------------------*/
   printf("Please enter your credentials\n");
   authenticate(ssl,hostname);
   printf("You are now connected to the VPN\n");
   //Monitor interfaces
   while (1) {
	   fd_set readFDSet;
	   FD_ZERO(&readFDSet);
	   FD_SET(sockfd, &readFDSet);
	   FD_SET(tunfd, &readFDSet);
	   select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

	   if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd,ssl);

	   if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd,ssl);

   }

}

