#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

sigset_t signal_mask;
pthread_t cf_waf_thread;
unsigned int cfLastIP = 0;
int cf_ban_req_len, cfQueueHead = 0, cfQueueTail = 0;
char *cfIPptr, cf_hosts[CF_NUM_HOSTS][64] = CF_HOSTS, cfQueue[CF_QUEUE_SIZE][16] = {0};

char cf_ban_req[512] = "POST /sslrelay/client/v4/accounts/" CF_ACCOUNT_ID "/rules/lists/" CF_LIST_ID "/items HTTP/1.1\r\nHost: " SSL_RELAY_HOSTNAME "\r\nX-Forwarded-For: api.cloudflare.com\r\nuser-agent: Fail1Ban\r\naccept: */*\r\ncontent-type: application/json\r\nx-auth-email: " CF_ACCOUNT_EMAIL "\r\nx-auth-key: " CF_API_KEY "\r\ncontent-length: 26\r\n\r\n[{\"ip\":\"255.255.255.255\"}]";

inline int strIdent(register char*, register char*);


void ban_ip_cf(char *ip_str) {
  unsigned int ip = str_to_ip(ip_str);
  if(ip != cfLastIP && strIdent(ip_str, "127.0.0.1") && strIdent(ip_str, WHITELIST_MY_IP)) {
    cfLastIP = ip;
    memcpy(cfQueue[cfQueueHead++], ip_str, 16);
    cfQueueHead &= CF_QUEUE_SIZE - 1;
    if(cfQueueHead - cfQueueTail < 4)
      pthread_kill(cf_waf_thread, SIGCONT);
  }
}


inline int cfHostCheck(char *host) {
  for(int i = 0; i < CF_NUM_HOSTS; i++) {
    if(!strIdent(cf_hosts[i], host))
      return 1; //match found
  }
  return 0; //not on cf
}


void* cf_waf() {
  int sig_caught, sockfd = 0;
  char abyss[16];
  struct addrinfo hints, *result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  getaddrinfo(SSL_RELAY_HOSTNAME, "http", &hints, &result);
  if(result->ai_family != AF_INET)
    return 0;

  while(1) {
    if(cfQueue[cfQueueTail][0] == 0) //queue empty
      sigwait(&signal_mask, &sig_caught); //sleep
    if(cfQueue[cfQueueTail][0] == 0) { //recover from desync
      cfQueueTail = cfQueueHead;
      continue;
    }

    sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(sockfd == -1)
      goto queueInc;

    if(connect(sockfd, result->ai_addr, result->ai_addrlen) == -1)
      goto queueIncClose;

    int len = strlen(cfQueue[cfQueueTail]);
    memset(cfIPptr + 7, ' ', 9);
    memcpy(cfIPptr, cfQueue[cfQueueTail], len);
    cfIPptr[len] = '"';

    write(sockfd, cf_ban_req, cf_ban_req_len);
    read(sockfd, abyss, 16);
    queueIncClose:
    close(sockfd);

    queueInc:
    cfQueue[cfQueueTail++][0] = 0;
    cfQueueTail &= CF_QUEUE_SIZE - 1;
  }

  freeaddrinfo(result);
}


void cfSetup() {
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGCONT);
  sigprocmask(SIG_SETMASK, &signal_mask, NULL); //block SIGCONT (inherited by all threads)

  cf_ban_req_len = strlen(cf_ban_req);
  cfIPptr = &cf_ban_req[cf_ban_req_len - 18];

  pthread_create(&cf_waf_thread, NULL, &cf_waf, NULL);
}

