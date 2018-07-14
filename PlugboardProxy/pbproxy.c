#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>


typedef struct {
	int sockfd;
	struct sockaddr_in ssh_addr;
	unsigned char *key;
} parameter_thread;

typedef struct {
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
} ctr_state;

void init_ctr(ctr_state *state, const unsigned char iv[16])
{
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
	* first call. */
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);

	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);

	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
}

void* doprocess(void *ptr)
{
	int n;
	int ssh_fd, ssh_done = 0;
	unsigned char buffer[4096];

	// set value in buffer to zero
	bzero(buffer, 4096);
	// ckeck if thread is properly initialised
	if (!ptr) pthread_exit(0); 
	printf("Starting new thread\n");
	parameter_thread *params = (parameter_thread *)ptr;
	int sock = params->sockfd;
	struct sockaddr_in ssh_addr = params->ssh_addr;
	unsigned char *key = params->key;
	ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (ssh_fd< 0) 
        {perror("ERROR opening socket"); exit(EXIT_FAILURE);}
	
	if (connect(ssh_fd, (struct sockaddr *)&ssh_addr, sizeof(ssh_addr)) < 0) {
		printf("Connection to ssh failed!\n");
		pthread_exit(0);
	} else {
		printf("Connection to ssh established!\n");
	}
	
	int flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		printf("read sock 1 flag error!\n");
		printf("Closing connections and exit thread!\n");
		close(sock);
		close(ssh_fd);
		free(params);
		pthread_exit(0);
	}
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	
	if (flags = fcntl(ssh_fd, F_GETFL) == -1) {
		printf("read ssh_fd flag error!\n");
		printf("Closing connections and exit thread!\n");
		close(sock);
		close(ssh_fd);
		free(params);
		pthread_exit(0);
	}
	fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);

	ctr_state state;
	AES_KEY aes_key;
	unsigned char iv[8];
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		exit(1);
	}

	while (1) {
		// to write back to the client by encrypting the data that is to be sent		
		while ((n = read(ssh_fd, buffer, 4096)) >= 0) {
			if (n > 0) {
				if(!RAND_bytes(iv, 8)) {
					fprintf(stderr, "Error generating random bytes.\n");
					exit(1);
				}

				char *tmp = (char*)malloc(n + 8);
				memcpy(tmp, iv, 8);
				unsigned char encryptiondata[n];
				init_ctr(&state, iv);
				AES_ctr128_encrypt(buffer, encryptiondata, n, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(tmp+8, encryptiondata, n);
				
				usleep(1000);

				write(sock, tmp, n + 8);
				
				free(tmp);
			}
			printf("INFO: Sending data to ssh client\n");
			
			if (ssh_done == 0 && n == 0)
				ssh_done = 1;
			
			if (n < 4096)
				break;
		}
		// to read the data received from client and decrypt it
		while ((n = read(sock, buffer, 4096)) > 0) {
			if (n < 8) {
				printf("Packet length smaller than 8!\n");
				close(sock);
				close(ssh_fd);
				free(params);
				pthread_exit(0);
			}
			
			memcpy(iv, buffer, 8);
			unsigned char decryptiondata[n-8];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer+8, decryptiondata, n-8, &aes_key, state.ivec, state.ecount, &state.num);

			write(ssh_fd, decryptiondata, n-8);

			if (n < 4096)
				break;
		};
		
                // end session if client exits 
		if (ssh_done == 1)
			break;
	}

	printf("Closing connectionsand exiting thread!\n");
	close(sock);
	close(ssh_fd);
	free(params);
	pthread_exit(0);
}

int start_server(struct sockaddr_in serv_addr, struct sockaddr_in ssh_addr, unsigned char *key)
{
	int sockfd, newsockfd;
	socklen_t clilen;
	struct sockaddr_in cli_addr;
	parameter_thread *param;
	pthread_t thread;

	// Creating socket file descriptor
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
    	{
        perror("socket failed");
        exit(EXIT_FAILURE);
    	}

	// Forcefully attaching socket to the port
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{perror("ERROR on binding");exit(EXIT_FAILURE);}

	// listen for connection request from client
	listen(sockfd, 5);
	clilen = sizeof(cli_addr);

	// allow multiple clients to connect to server
	while (1) {
		param = (parameter_thread *)malloc(sizeof(parameter_thread));
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		param->sockfd = newsockfd;
		param->ssh_addr = ssh_addr;
		param->key = key;
		// Create new thread for connection with client
		if (newsockfd > 0) {
			pthread_create(&thread, 0, doprocess, (void *)param);
			pthread_detach(thread);
		} else {
			perror("ERROR on accept");
			free(param);
			exit(EXIT_FAILURE);
		}
	}
	return 0; 
}

int start_client(struct sockaddr_in serv_addr, unsigned char *key)
{
	int sockfd, n;
	unsigned char buffer[4096];

	// Creating socket file descriptor
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		{perror("ERROR opening socket");exit(EXIT_FAILURE);}
	
	// Connect the client to server port
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{perror("Connection failed");exit(EXIT_FAILURE);}

	// Check if host kernel supports the specified operation
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

	int flags = fcntl(sockfd, F_GETFL);
	if (flags == -1) {
		printf("read sockfd flag error!\n");
		close(sockfd);
	}
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	bzero(buffer, 4096);

	ctr_state state;
	unsigned char iv[8];
	AES_KEY aes_key;

	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
		printf("Set encryption key error!\n");
		exit(1);
	}

	while (1) {
		// to send/write encrypted packets from client to server
		while ((n = read(STDIN_FILENO, buffer, 4096)) > 0) {
			// initialise unique initialization vector randomly for each session
			if (!RAND_bytes(iv, 8)) {
				printf("Error generating random bytes.\n");
				exit(1);
			}
			// encrypt the data to be sent
			char *tmp = (char*)malloc(n + 8);
			memcpy(tmp, iv, 8);
			unsigned char encryptiondata[n];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer, encryptiondata, n, &aes_key, state.ivec, state.ecount, &state.num);
			memcpy(tmp + 8, encryptiondata, n);
			// write data at server socket
			write(sockfd, tmp, n + 8);
			
			free(tmp);

			if (n < 4096)
				break;
		}
		//read and decrypt the packet data received from the server to client
		while ((n = read(sockfd, buffer, 4096)) > 0) {
			if (n < 8) {
				fprintf(stderr, "Packet length smaller than 8!\n");
				close(sockfd);
				return 0;
			}
			// decrypt data received in buffer
			memcpy(iv, buffer, 8);
			unsigned char decryptiondata[n - 8];
			init_ctr(&state, iv);
			AES_ctr128_encrypt(buffer + 8, decryptiondata, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

			write(STDOUT_FILENO, decryptiondata, n - 8);

			if (n < 4096)
				break;
		}
	}
	return 0;
}

// to obtain the key from the keyfile specified by the user
unsigned char* read_keyfile(char* filename)
{
	unsigned char *buffer = NULL;
	long length;
	FILE *f = fopen (filename, "rb");

	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
		{
			fread (buffer, 1, length, f);
		}
		fclose (f);
	}
	return buffer;
}

int main(int argc, char *argv[])
{
	int opt, server_port = 0, dst_port;
	char *dst_addr = NULL;
	unsigned char *keyfile = NULL;
	int server_mode = 0;

	struct hostent *host;
	// optain the input arguments from cmd 
	while ((opt = getopt(argc, argv, "l:k:")) != -1) {
		switch (opt) {
		case 'l':
			server_mode = 1;
			server_port = (int)strtol(optarg, NULL, 10);
			break;
		case 'k':
			keyfile = read_keyfile(optarg);
			if (!keyfile) {
				fprintf(stderr, "read key file failed!\n");
				return 0;
			}
			break;
		default:
			fprintf(stderr, "pbproxy [-l port] -k keyfile destination port!\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind == argc - 2) {
		dst_addr = argv[optind];
		dst_port = (int)strtol(argv[optind + 1], NULL, 10);
	} else {
		fprintf(stderr, "optind: %d, argc: %d\n", optind, argc);
		fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
	// check if keyfile is specified or is empty
	if (keyfile == NULL) {
		fprintf(stderr, "keyfile must be specified!\n");
		exit(EXIT_FAILURE);
	}

	printf("keyfile = %s\n", keyfile);
	printf("server_mode %s\n", server_mode==1 ?"on":"off" );
	printf("server_port = %d\n", server_port);
	printf("dst_addr = %s\n", dst_addr);
	printf("dst_port = %d\n", dst_port);
        
	// if destination host address is specified , get the host name
	if ((host = gethostbyname(dst_addr)) == 0) {
		fprintf(stderr, "Could not get host by name!\n");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in sock_addr, ssh_addr;
	bzero(&sock_addr, sizeof(sock_addr));
	bzero(&ssh_addr, sizeof(ssh_addr));

	// check in which mode to execute based on the cmd arguments
	if (server_mode == 0) {
		// run in client mode
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;
		sock_addr.sin_port = htons(dst_port);
		start_client(sock_addr, keyfile);
		
	} else {
		// run in server mode
		sock_addr.sin_family = AF_INET;
		sock_addr.sin_addr.s_addr = htons(INADDR_ANY);
		sock_addr.sin_port = htons(server_port);

		ssh_addr.sin_family = AF_INET;
		ssh_addr.sin_port = htons(dst_port);
		ssh_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;
		start_server(sock_addr, ssh_addr, keyfile);

		
	}
	free(keyfile);
	exit(EXIT_SUCCESS);
}
