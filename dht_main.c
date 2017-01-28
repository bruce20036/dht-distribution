/* For crypt */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/signal.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "dht.h"

#define MAX_BOOTSTRAP_NODES 20
static struct sockaddr_storage bootstrap_nodes[MAX_BOOTSTRAP_NODES];
static int num_bootstrap_nodes = 0;
const char *known_bootstrap_nodes[] = {
    "router.utorrent.com",
    "router.bittorrent.com",
    "dht.transmissionbt.com",
};

struct hash_node{
    const unsigned char *a;
    struct hash_node *next;
};

static volatile sig_atomic_t dumping = 0, searching = 0, exiting = 0;

static void
sigdump(int signo)
{
    dumping = 1;
}

static void
sigtest(int signo)
{
    searching = 1;
}

static void
sigexit(int signo)
{
    exiting = 1;
}

static void
init_signals(void)
{
    struct sigaction sa;
    sigset_t ss;

    sigemptyset(&ss);
    sa.sa_handler = sigdump;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigtest;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGUSR2, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = sigexit;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

unsigned char hash[20] = {
    0x54, 0x57, 0x87, 0x89, 0xdf, 0xc4, 0x23, 0xee, 0xf6, 0x03,
    0x1f, 0x81, 0x94, 0xa9, 0x3a, 0x16, 0x98, 0x8b, 0x72, 0x7b
};

/*If the data exist, then copy the result to the "<info_hash>.txt"*/
static void
callback(void *closure,
         int event,
         const unsigned char *info_hash,
         const void *data, size_t data_len)
{
    if(event == DHT_EVENT_SEARCH_DONE)
        printf("Search done.\n");
    else if(event == DHT_EVENT_VALUES){
        printf("Received %d values.\n", (int)(data_len / 6));
        int i;
        char *file_path = "DHT-Values/";
        char *file_ext = ".txt";
        char *peer_file = (char*)calloc(strlen(file_path)+40+strlen(file_ext), sizeof(char));
        char trans[40];
        for(i=0; i<20; i++){
            char t1 = (info_hash[i]>>4);
            char t2 = (info_hash[i]&0x0F);
            trans[i] = (t1>=0&&t1<=9)? '0'+t1 : 'W'+t1;
            trans[i+1] = (t2>=0&&t2<=9)? '0'+t2 : 'W'+t2;
        }
        if(peer_file!=NULL){
            strcat(peer_file, file_path);
            strcat(peer_file, (const char*)trans);
            strcat(peer_file, file_ext);
        }
        else{
            perror("Can't calloc in callback.\n");
            return;
        }
        
        FILE *pfile = fopen(peer_file, "w");
        const unsigned char *value = (const unsigned char*) data;
        for(i=0; i<(int)(data_len / 6); i++){
            for(int k=0; k<4; k++){
                fprintf(pfile, "%d ", value[k+i]);
            }
            fprintf(pfile, "%d\n", (value[4+i]<<8)+value[5+i]);
        }
        fclose(pfile);
    }
}

static unsigned char buf[4096];

int
main(int argc, char **argv)
{
    int i, rc, fd;
    FILE *pfile;
    int s = -1, s6 = -1;
    int announce = 0;
    int port = 6881;
    int announce_port = 0;
    int opt;
    int have_id = 0;
    int hash_from_file = 0;         //input "hash" from file
    int sha_from_file = 0;          //input "name" from file and output sha1
    struct hash_node *hhead = NULL;
    time_t tosleep = 0;
    unsigned char myid[20];
    char *id_file = "dht.id";
    char *bootstrap_file = "dht.bootstrap";
    char *hash_file = "dht_hash.txt";
    char *input_sha1 = "dht_sha1_input.txt";
    char *output_sha1 = "dht_sha1_output.txt";
    struct sockaddr_in sin;
    struct sockaddr_storage from;
    socklen_t fromlen;

    while(1) {
        opt = getopt(argc, argv, "ap:sf");
        if(opt < 0)
            break;

        switch(opt) {
            case 'a':
                announce = 1;
                break;
            case 'p':
                if(strlen(optarg)>=6)
                    goto usage;
                port = atoi(optarg);
                break;
            case 's':
                if(hash_from_file){
                    perror("Only one of -s and -f can be performed, or none of them\n");
                    goto usage;
                }
                sha_from_file = 1;
                break;
            case 'f':
                if(sha_from_file){
                    perror("Only one of -f and -s can be performed, or none of them\n");
                    goto usage;
                }
                hash_from_file = 1;
                break;
            default:
                goto usage;
        }
    }

    if(announce){
        if(port==0){
            perror("Port should not be 0\n");
            goto usage;
        }
        else{
            announce_port = port;
        }
    }

    //Set up socket
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    s = socket(PF_INET, SOCK_DGRAM, 0);
    if(s<0){
        perror("socket(IPv4)");
    }
    if(s>=0){
        rc = bind(s, (struct sockaddr*)&sin, sizeof(sin));
        if(rc < 0) {
            perror("bind(IPv4)");
            exit(1);
        }
    }

    //Configure myid
    /* Ids need to be distributed evenly, so you cannot just use your
       bittorrent id.  Either generate it randomly, or take the SHA-1 of
       something. */
    fd = open(id_file, O_RDONLY);
    if(fd >= 0) {
        rc = read(fd, myid, 20);
        if(rc == 20)
            have_id = 1;
        close(fd);
    }
    
    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        perror("open(random)");
        exit(1);
    }

    if(!have_id) {
        int ofd;

        rc = read(fd, myid, 20);
        if(rc < 0) {
            perror("read(random)");
            exit(1);
        }
        have_id = 1;
        close(fd);

        ofd = open(id_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(ofd >= 0) {
            rc = write(ofd, myid, 20);
            if(rc < 20)
                unlink(id_file);
            close(ofd);
        }
    }

    {
        unsigned seed;
        read(fd, &seed, sizeof(seed));
        srandom(seed);
    }
    close(fd);
    //end myid

    //bootstrap nodes
    {
        struct addrinfo hints, *info;
        int j = 0;
        while(j<3){
            memset(&hints, 0, sizeof(hints));
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_family = AF_INET;
            rc = getaddrinfo(known_bootstrap_nodes[j++], "6881", &hints, &info);
            if(rc != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
                exit(1);
            }
            memcpy(&bootstrap_nodes[num_bootstrap_nodes++],info->ai_addr, info->ai_addrlen);
            freeaddrinfo(info);
        }
        //bootstrap from previous good nodes
        pfile = fopen(bootstrap_file, "r");
        if(pfile){
            struct sockaddr_in sin_tmp;
            while(fread(&sin_tmp, sizeof(struct sockaddr_in), 1, pfile)==1 && 
                  num_bootstrap_nodes<MAX_BOOTSTRAP_NODES){
                memset(&hints, 0, sizeof(hints));
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_family = AF_INET;
                char *addr_tmp = inet_ntoa(sin_tmp.sin_addr);
                char post_tmp[4];
                snprintf(post_tmp, 5, "%d", ntohs(sin_tmp.sin_port));
                getaddrinfo(addr_tmp, post_tmp, &hints, &info);
                if(rc != 0) {
                    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
                    exit(1);
                }
                memcpy(&bootstrap_nodes[num_bootstrap_nodes++],info->ai_addr, info->ai_addrlen);
                freeaddrinfo(info);
            }
        }
    }
    //end bootstrap

    //Set up by given inputs and output SHA1 result
    if(sha_from_file){
        FILE *infile = fopen(input_sha1, "r");
        FILE *outfile = fopen(output_sha1, "w");
        if(infile==NULL || outfile==NULL){
            perror("Can't open dht_sha1_input.txt or dht_sha1_output.txt\n");
            exit(1);
        }
        char input[256];
        int j=0;
        printf("SHA1 Encoding...\n");
        while(fgets(input, 256, infile)!=NULL){
            if(input[0]=='\n')
                break;
            int len = input[strlen(input)-1]=='\n'? ((int)strlen(input))-1 : (int)strlen(input);
            unsigned char *output = (unsigned char*)calloc(20, sizeof(char));
            char *tmp = calloc(len, sizeof(char));
            memcpy(tmp, input, len);
            printf("%s -> ", tmp);
            SHA1((unsigned char*)tmp, len, output);
            struct hash_node *n = (struct hash_node*)malloc(sizeof(struct hash_node));
            if(n==NULL){
                printf("No space to declare. Only %d searches can be searched.\n", j);
            }
            else{
                n->a = output;
                if(hhead==NULL){
                    n->next = NULL;
                    hhead = n;
                }
                else{
                    n->next = hhead;
                    hhead = n;
                }
            }
            for(int i=0; i<20; i++){
                fprintf(outfile, "%02x", output[i]);
                printf("%02x", output[i]);
            }
            fprintf(outfile, "\n");
            puts("");
            j++;
            for(int k=0; k<20; k++)
                printf("%02x", hhead->a[k]);
            puts(""); 
        }
        if(hhead==NULL){
            perror("The file is empty or wrong.\n");
            exit(1);
        }
        else
            searching = 1;
    }
    //End SHA1

    //Set up hash from file
    if(hash_from_file){
        unsigned tmp;
        pfile = fopen(hash_file, "r");
        if(pfile==NULL){
            perror("Hash file does not exist\n");
            exit(1);
        }
        int j=0;
        printf("Import Info-hash....\n");
        while(fscanf(pfile, "%02x", &tmp)!=EOF){
            unsigned char *f_input = (unsigned char*) calloc(20, sizeof(char));
            for(i=0; i<20; i++){
                f_input[i] = tmp;
                if(i!=19){
                    if(fscanf(pfile, "%02x", &tmp)==EOF){
                        perror("Entries in hash file is not right.\n");
                        fclose(pfile);
                        exit(1);
                    }
                }
            }
            struct hash_node *n = (struct hash_node*) malloc(sizeof(struct hash_node));
            if(n==NULL){
                printf("No space to declare. Only %d searches can be searched.\n", j);
            }
            else{
                n->a = f_input;
                if(hhead==NULL){
                    n->next = NULL;
                    hhead = n;
                }
                else{
                    n->next = hhead;
                    hhead = n;
                }
            }
            j++;
            //print import info-hash
            for(int k=0; k<20; k++)
                printf("%02x", hhead->a[k]);
            puts(""); 
        }
        if(hhead==NULL){
            perror("The file is empty or wrong.\n");
            exit(1);
        }
        else
            searching = 1;
        fclose(pfile);
    }
    //End hash file

    //If no import from file, then set default search
    if(!hash_from_file&&!sha_from_file)
        searching = 1;

    /* If you set dht_debug to a stream, every action taken by the DHT will
       be logged. */
    dht_debug = stdout;

    /* Init the dht.  This sets the socket into non-blocking mode. */
    rc = dht_init(s, s6, myid, (unsigned char*)"JC\0\0");
    if(rc < 0) {
        perror("dht_init");
        exit(1);
    }

    init_signals();

    /* For bootstrapping, we need an initial list of nodes.  This could be
       hard-wired, but can also be obtained from the nodes key of a torrent
       file, or from the PORT bittorrent message.

       Dht_ping_node is the brutal way of bootstrapping -- it actually
       sends a message to the peer.  If you're going to bootstrap from
       a massive number of nodes (for example because you're restoring from
       a dump) and you already know their ids, it's better to use
       dht_insert_node.  If the ids are incorrect, the DHT will recover. */
    for(i = 0; i < num_bootstrap_nodes; i++) {
        dht_ping_node((struct sockaddr*)&bootstrap_nodes[i],
                      sizeof(bootstrap_nodes[i]));
        usleep(random() % 100000);
    }

    //Start main progess
    while(1) {
        struct timeval tv;
        fd_set readfds;
        tv.tv_sec = tosleep;
        tv.tv_usec = random() % 1000000;

        FD_ZERO(&readfds);
        if(s >= 0)
            FD_SET(s, &readfds);
        rc = select(s + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0) {
            if(errno != EINTR) {
                perror("select\n");
                sleep(1);
            }
        }

        if(exiting)
            break;

        if(rc > 0) {
            fromlen = sizeof(from);
            if(s >= 0 && FD_ISSET(s, &readfds))
                rc = recvfrom(s, buf, sizeof(buf) - 1, 0,
                              (struct sockaddr*)&from, &fromlen);
            else
                abort();
        }

        if(rc > 0) {
            buf[rc] = '\0';
            rc = dht_periodic(buf, rc, (struct sockaddr*)&from, fromlen,
                              &tosleep, callback, NULL);
        } else {
            rc = dht_periodic(NULL, 0, NULL, 0, &tosleep, callback, NULL);
        }
        if(rc < 0) {
            if(errno == EINTR) {
                continue;
            } else {
                perror("dht_periodic");
                if(rc == EINVAL || rc == EFAULT)
                    abort();
                tosleep = 1;
            }
        }

        /* We perform announce while searching. The default maximum search number
           at the same time is 1024, if the total amount is out of the bound, we'll
           try later to see if there are spaces created. Since peers expire announced 
           data after 30 minutes, it's a good idea to reannounce every 28 minutes or so. */
        if(searching) {
            if(hash_from_file||sha_from_file){
                printf("Search: ");
                for(int j=0; j<20; j++)
                    printf("%02x", hhead->a[j]);
                puts("");
                dht_search(hhead->a, announce_port, AF_INET, callback, NULL);
                if(errno==ENOSPC)
                    printf("No space for further search, try later.\n");
                else{
                    struct hash_node *tmp = hhead;
                    hhead = hhead->next;
                    free(tmp);
                    if(hhead==NULL)
                        searching = 0;
                } 
            }
            else{
                printf("Search: ");
                for(int j=0; j<20; j++)
                    printf("%02x", hash[j]);
                puts("");
                dht_search(hash, announce_port, AF_INET, callback, NULL);
                searching = 0;
            }
        }

        /* For debugging, or idle curiosity. */
        if(dumping) {
            dht_dump_tables(stdout);
            dumping = 0;
        }
    }

    {
        struct sockaddr_in sin[500];
        struct sockaddr_in6 sin6[500];
        int num = 500, num6 = 500;
        i = dht_get_nodes(sin, &num, sin6, &num6);
        printf("Found %d (%d + %d) good nodes.\n", i, num, num6);

        //Store good nodes to file
        if(num>0){
            pfile = fopen(bootstrap_file, "w");
            i = 0;
            while(i<num){
                fwrite(&sin[i++], sizeof(struct sockaddr_in), 1, pfile);
            }
            fclose(pfile);
        }
    }

    dht_uninit();
    return 0;

usage:
    printf("Usage: dht-example [-a announce] [-p port] [-s sha1 from file] [-f hash from file]\n");
    exit(1);
}

/* Functions called by the DHT. */
int
dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return 0;
}

/* We need to provide a reasonably strong cryptographic hashing function.
   Here's how we'd do it if we had RSA's MD5 code. */
#if 1
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    static MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, v1, len1);
    MD5_Update(&ctx, v2, len2);
    MD5_Update(&ctx, v3, len3);
    MD5_Final((unsigned char*)hash_return, &ctx);
}
#else
/* But for this example, we might as well use something weaker. */
void
dht_hash(void *hash_return, int hash_size,
         const void *v1, int len1,
         const void *v2, int len2,
         const void *v3, int len3)
{
    const char *c1 = v1, *c2 = v2, *c3 = v3;
    char key[9];                /* crypt is limited to 8 characters */
    int i;

    memset(key, 0, 9);
#define CRYPT_HAPPY(c) ((c % 0x60) + 0x20)

    for(i = 0; i < 2 && i < len1; i++)
        key[i] = CRYPT_HAPPY(c1[i]);
    for(i = 0; i < 4 && i < len1; i++)
        key[2 + i] = CRYPT_HAPPY(c2[i]);
    for(i = 0; i < 2 && i < len1; i++)
        key[6 + i] = CRYPT_HAPPY(c3[i]);
    strncpy(hash_return, crypt(key, "jc"), hash_size);
}
#endif

int
dht_random_bytes(void *buf, size_t size)
{
    int fd, rc, save;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0)
        return -1;

    rc = read(fd, buf, size);

    save = errno;
    close(fd);
    errno = save;

    return rc;
}
