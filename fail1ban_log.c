#include <unistd.h>
#include <fcntl.h> //open
#include <sys/stat.h> //mkfifo
#include <pthread.h>
#include <string.h>
#include "ip_str_convert.c"

#if __has_include("config.local.h")
  #include "config.local.h"
#else
  #include "config.h"
#endif

#ifdef CF
  #include "cloudflare.c"
#endif

pthread_t nginx_thread, ssh_thread;
unsigned int warnings[RECENT_WARNINGS];
int f1b_procfs, warning_tail = 0;
char lastIP[16] = {0}, nbuff[BUFFER_SIZE], sbuff[BUFFER_SIZE];



inline int strIdent(register char *s1, register char *s2) {
  while(*s1 == *s2 && *s1 && *s2) {
    s1 += 1;
    s2 += 1;
  }
  return (*s1 | *s2); // 0 = identical
}



inline char* strLine(register char *string, register char *substring, int progress) {
  register char *a, *b;

  while(*string && *string != '\n') {
    if(*string++ != *substring) continue;
    a = string;
    b = substring + 1;
    while(*a == *b) {
      a += 1;
      b += 1;
      if(*b == 0) return string - 1;
    }
  }
  return progress ? string : NULL;
}



void ban_ip(char *ip_str) {
  if(strIdent(ip_str, lastIP) && strIdent(ip_str, "127.0.0.1") && strIdent(ip_str, WHITELIST_SERVER_IP) && strIdent(ip_str, WHITELIST_MY_IP)) {
    write(f1b_procfs, ip_str, 15);
    strcpy(lastIP, ip_str);
  }
}



//check if ip has 2 recent warnings
int warning_check(char *ip_str) {
  register int warn = 0;
  unsigned int ip = str_to_ip(ip_str);

  for(int i = 0; i < RECENT_WARNINGS; i++) //check warnings
    warn += (ip == warnings[i]);

  if(warn < 2) { //add warning, don't ban
    warnings[warning_tail++] = ip;
    warning_tail &= RECENT_WARNINGS - 1;
  }

  return (warn == 2); //ban if 2 warning exist
}



void nginx_fw(void) {
  char *ptr = nbuff;

  while(*ptr) {
    //find start of log line
    while(*ptr && *ptr != '~')
      ptr += 1;
    if(*ptr == 0) //EOF
      return;

    char *httpCode = ++ptr;
    while(*ptr > ' ')
      ptr += 1;
    if(*ptr != ' ') return; //EOF (fragmented logs)

    char *ip = ++ptr;
    while(*ptr > '#')
      ptr += 1;
    if(*ptr != '#') return; //EOF (fragmented logs)
    *ptr++ = 0; //null term ip str

    //ignore ipv6
    if(ptr - ip > 16 || ip[4] == ':')
      continue;

    #ifdef CF
    char *host = ptr;
    while(*ptr > ',')
      ptr += 1;
    if(*ptr != '\n') return; //EOF (fragmented logs)
    *ptr++ = 0; //null term host str
    #endif

    //if(httpCode[0] == '2') continue;

    //rule 444 && rule 400
    if(httpCode[1] == '4' || (httpCode[0] == '4' && httpCode[2] == '0')) {
      #ifdef CF
      if(cfHostCheck(host))
        ban_ip_cf(ip);
      else
      #endif
        ban_ip(ip);
    }

    //rule 404
    if(httpCode[0] == '4' && httpCode[1] == '0' && httpCode[2] == '4') {
      if(warning_check(ip)) {
        #ifdef CF
        if(cfHostCheck(host))
          ban_ip_cf(ip);
        else
        #endif
          ban_ip(ip);
      }
    }

    //rule 301
    if(httpCode[0] == '3' && httpCode[2] == '1') {
      if(warning_check(ip))
        ban_ip(ip);
    }
  }
}



void ssh_fw(void) {
  register char *ptr = sbuff;

  while(*ptr) {
    ptr = strLine(ptr, "sshd", 1);
    if(*ptr < ' ') goto nextLine; //next line or EOF

    if(strLine(ptr, "Failed", 0) || strLine(ptr, "Invalid", 0)) { //auth failed

      findNumber:
      while(*ptr && *ptr != '\n' && (*ptr > '9' || *ptr < '1')) //find number in current line
        ptr += 1;

      if(*ptr < ' ') goto nextLine;

      char *ip = ptr;
      int octet = 0;
      while(*ptr >= '.' && *ptr <= '9') { //find end of number / ip str
        octet += (*ptr == '.');
        ptr += 1;
      }

      if(*ptr == 0) return; //partial line / fragmented buff

      if(ptr - ip > 6 && ptr - ip < 16 && octet == 3) { //valid ipv4
        if(*ptr == '\n' && ptr[1] != 0) //ip at EOL but not EOF
          ptr[1] = '\n';
        *ptr++ = 0; //term ip str
        ban_ip(ip); //ban
      }
      else goto findNumber;
    }

    nextLine: //advance to next line
    while(*ptr && *ptr != '\n')
      ptr += 1;
    ptr += (*ptr == '\n');
  }
}



void* nginx_log(void* x) {
  int fd, bytesRead;

  mkfifo(NGINX_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  chmod( NGINX_PIPE, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  fd = open(NGINX_PIPE, O_RDONLY);

  while(1) {
    bytesRead = read(fd, nbuff, sizeof(nbuff) - 1);
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
    bytesRead = read(fd, sbuff, sizeof(sbuff) - 1);
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

  f1b_procfs = open("/proc/" PROCFS_NAME, O_WRONLY);
  if(f1b_procfs < 3)
    return 1;

  #ifdef CF
    cfSetup();
  #endif

  pthread_create(&nginx_thread, NULL, &nginx_log, NULL);
  pthread_create(&ssh_thread, NULL, &ssh_log, NULL);

  while(1) pause();

  return 0;
}

