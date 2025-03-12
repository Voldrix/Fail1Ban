#include <unistd.h>
#include <fcntl.h> //open
#include <sys/stat.h> //mkfifo
#include <pthread.h>
#include <string.h>
#include "ip_str_convert.c"

#ifdef CF
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
sigset_t signal_mask;
void* cf_waf();
#endif

#if __has_include("config.local.h")
#include "config.local.h"
#else
#include "config.h"
#endif

int f1b_procfs, cf_ban_req_len, warning_tail = 0;
char nbuff[BUFFER_SIZE], sbuff[BUFFER_SIZE];
pthread_t nginx_thread, ssh_thread, cf_waf_thread;
unsigned int warnings[RECENT_WARNINGS], cfQueue[CF_QUEUE_SIZE] = {0};
int cfQueueHead = 0, cfQueueTail = 0;
char cf_ban_req[1024], lastIP[16] = {0}, *cfIPptr;



inline int strIdent(register char *s1, register char *s2) {
  while(*s1 == *s2 && *s1 && *s2) {
    s1 += 1;
    s2 += 1;
  }
  return (*s1 | *s2); // 0 = identical
}



void ban_ip(char *ip_str) {
  if(strIdent(ip_str, "127.0.0.1") && strIdent(ip_str, WHITELIST_MY_IP) && strIdent(ip_str, lastIP)) {
    write(f1b_procfs, ip_str, 15);
    strcpy(lastIP, ip_str);
  }
}


#ifdef CF
void ban_ip_cf(char *ip_str) {
  if(strIdent(ip_str, "127.0.0.1") && strIdent(ip_str, WHITELIST_MY_IP)) {
    unsigned int ip = str_to_ip(ip_str);
    cfQueue[cfQueueHead++] = ip;
    cfQueueHead &= CF_QUEUE_SIZE - 1;
    if(cfQueueHead - cfQueueTail < 4)
      pthread_kill(cf_waf_thread, SIGCONT);
  }
}
#endif


//check if ip has 2 recent warnings
//if they do, ban them (return 1)
//if not add their ip to recent warnings list
int warning_check(char *ip_str) {
  register int warn = 0;
  unsigned int ip = str_to_ip(ip_str);

  for(int i = 0; i < RECENT_WARNINGS; i++)
    warn += (ip == warnings[i]);

  if(warn < 2) { //add warning, don't ban
    warnings[warning_tail++] = ip;
    warning_tail &= RECENT_WARNINGS - 1;
  }

  return (warn == 2); //ban if 2 warning exist
}



void nginx_fw(void) {
  char *ip, *ip_end, *ptr = nbuff, ipv6;

  while(*ptr) {
    //find start of log line
    while(*ptr && *ptr != '~')
      ptr += 1;
    if(*ptr == 0) //EOF
      return;

    ip = &ptr[5];
    ip_end = ip + 7; //min ip length
    while(*ip_end && *ip_end != '#')
      ip_end += 1;
    *ip_end++ = 0; //null term ip str

    ipv6 = (ip_end - ip > 16); //ignore ipv6
    if(ipv6 || !strIdent(ip, WHITELIST_SERVER_IP))
      goto loopNextLog;

    //rule 444 && rule 400
    if(ptr[2] == '4' || (ptr[1] == '4' && ptr[3] == '0')) {
      #ifdef CF
      if(ip_end[1] == '' || ip_end[1] == '') //set this to uniquely identify domains on cloudflare
        ban_ip_cf(ip);
      else
      #endif
        ban_ip(ip);
    }

    //rule 404
    if(ptr[1] == '4' && ptr[2] == '0' && ptr[3] == '4') {
      if(warning_check(ip)) {
        #ifdef CF
        if(ip_end[1] == '' || ip_end[1] == '') //set this to uniquely identify domains on cloudflare
          ban_ip_cf(ip);
        else
        #endif
          ban_ip(ip);
      }
    }

    //rule 301
    if(ptr[1] == '3' && ptr[3] == '1') {
      if(warning_check(ip))
        ban_ip(ip);
    }

    //passed all rules
    loopNextLog:
    ptr = ip_end;
  } //end rules
}



void ssh_fw(void) {
  register char *ptr = sbuff;
  char *ip;

  while(*ptr) {
    while(*ptr && *ptr != ']') //skip past datestamp to actual msg
      ptr += 1;
    if(!*ptr) return;
    ptr += 3;
    if(*ptr != 'A' && *ptr != 'R' && *ptr != 'D' && *ptr != 'C') { //auth fail
      while(*ptr && *ptr != '\n' && (*ptr > '9' || *ptr < '1')) //find ipv4 in current line
        ptr += 1;
      if(*ptr && *ptr != '\n' && (ptr[6] == '.' || (ptr[6] >= '0' && ptr[6] <= '9'))) { //confirm it is an ipv4
        ip = ptr;
        ptr += 7; //min ipv4 length
        while(*ptr && *ptr != ' ' && *ptr != '\n')
          ptr += 1;
        ptr[1] = (*ptr == 0) ? 0 : ptr[1]; //dup null term if this is the last line, to break loop. so we can insert line term
        *ptr++ = 0; //insert line term. ip str
        if(ptr - ip < 17 && strIdent(ip, WHITELIST_SERVER_IP))
          ban_ip(ip); //ban
      }
    }
    while(*ptr && *ptr != '\n') //next line or EOF
      ptr += 1;
    ptr += (*ptr == '\n'); //next line
  }
}



void* nginx_log(void* x) {
  int fd, bytesRead;

  mkfifo(NGINX_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  chmod( NGINX_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  fd = open(NGINX_PIPE, O_RDONLY);

  while(1) {
    bytesRead = read(fd, nbuff, sizeof(nbuff) - 2);
    if(bytesRead <= 0)
      continue;
    nbuff[bytesRead] = 0;

    nginx_fw();
  }

  close(fd);
  return 0;
}



void* ssh_log(void* x) {
  int fd, bytesRead;

  mkfifo(SSH_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  chmod( SSH_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  fd = open(SSH_PIPE, O_RDONLY);

  while(1) {
    bytesRead = read(fd, sbuff, sizeof(sbuff) - 2);
    if(bytesRead <= 0)
      continue;
    sbuff[bytesRead] = 0;

    ssh_fw();
  }

  close(fd);
  return 0;
}



int main(void) {
  daemon(0, 0);

  f1b_procfs = open(F1B_PROCFS, O_WRONLY);
  if(f1b_procfs < 1)
    return 1;

  pthread_create(&nginx_thread, NULL, &nginx_log, NULL);
  pthread_create(&ssh_thread, NULL, &ssh_log, NULL);

  #ifdef CF
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGCONT);
  sigprocmask(SIG_SETMASK, &signal_mask, NULL); //block SIGCONT (inherited by all threads)

  strcpy(cf_ban_req, "POST /sslrelay/client/v4/accounts/");
  strcat(cf_ban_req, CF_ACCOUNT_ID);
  strcat(cf_ban_req, "/rules/lists/");
  strcat(cf_ban_req, CF_LIST_ID);
  strcat(cf_ban_req, "/items HTTP/1.1\r\nHost: ");
  strcat(cf_ban_req, SSL_RELAY_HOSTNAME);
  strcat(cf_ban_req, "\r\nX-Forwarded-For: api.cloudflare.com\r\nuser-agent: Fail1Ban\r\naccept: */*\r\ncontent-type: application/json\r\nx-auth-email: ");
  strcat(cf_ban_req, CF_ACCOUNT_EMAIL);
  strcat(cf_ban_req, "\r\nx-auth-key: ");
  strcat(cf_ban_req, CF_API_KEY);
  strcat(cf_ban_req, "\r\ncontent-length: 26\r\n\r\n[{\"ip\":\"255.255.255.255\"}]");

  cf_ban_req_len = strlen(cf_ban_req);
  cfIPptr = cf_ban_req + cf_ban_req_len - 18;

  pthread_create(&cf_waf_thread, NULL, &cf_waf, NULL);
  #endif

  while(1) pause();

  return 0;
}


#ifdef CF
void* cf_waf() {
  int sig_caught, sockfd = 0;
  unsigned int _lastIP = 0;
  char ip_str[16], abyss[16];
  struct addrinfo hints, *result;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  getaddrinfo(SSL_RELAY_HOSTNAME, "http", &hints, &result);
  if(result->ai_family != AF_INET)
    return 0;

  while(1) {
    if(cfQueue[cfQueueTail] == 0) //queue empty
      sigwait(&signal_mask, &sig_caught); //sleep
    if(!cfQueue[cfQueueTail]) {
      cfQueueTail = cfQueueHead;
      continue;
    }

    if(cfQueue[cfQueueTail] == _lastIP)
      goto queueInc;

    sockfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(sockfd == -1)
      goto queueInc;

    if(connect(sockfd, result->ai_addr, result->ai_addrlen) == -1)
      goto queueIncClose;

    _lastIP = cfQueue[cfQueueTail];

    ip_to_str(cfQueue[cfQueueTail], (unsigned char*)ip_str);
    int len = strlen(ip_str);
    memset(cfIPptr + 7, ' ', 9);
    memcpy(cfIPptr, ip_str, len);
    cfIPptr[len] = '"';

    write(sockfd, cf_ban_req, cf_ban_req_len);
    read(sockfd, abyss, 16);
    queueIncClose:
    close(sockfd);

    queueInc:
    cfQueue[cfQueueTail++] = 0;
    cfQueueTail &= CF_QUEUE_SIZE - 1;
  }

  freeaddrinfo(result);
}
#endif

