#include <unistd.h>
#include <fcntl.h> //open
#include <sys/file.h>
#include <sys/stat.h> //mkfifo
#include <pthread.h>
#include "ip_str_convert.c"

#define NGINX_PIPE "/run/fail1ban-nginx"
#define SSH_PIPE "/run/fail1ban-ssh"
#define F1B_PROCFS "/proc/fail1ban"
#define BUFFER_SIZE 1024
#define RECENT_WARNINGS 16 //power of 2

#define WHITELIST_SERVER_IP "0.0.0.0"
#define WHITELIST_MY_IP "0.0.0.0"


int f1b_procfs, warning_tail = 0;
char nbuff[BUFFER_SIZE], sbuff[BUFFER_SIZE], lastIP[16] = {0};
unsigned int warnings[RECENT_WARNINGS];


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

  return (warn == 2); //ban if 2 warnings exist
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
    while(*ip_end != '#')
      ip_end += 1;
    *ip_end++ = 0; //null term ip str

    ipv6 = (ip_end - ip > 18); //ignore ipv6
    if(ipv6 || !strIdent(ip, WHITELIST_SERVER_IP)) {
      ptr = ip_end;
      continue;
    }

    //rule 444 && rule 400
    if(ptr[2] == '4' || (ptr[1] == '4' && ptr[3] == '0')) {
      ban_ip(ip);
    }

    //rule 404 && 301
    if((ptr[1] == '4' && ptr[2] == '0' && ptr[3] == '4') || (ptr[1] == '3' && ptr[3] == '1')) {
      if(warning_check(ip))
        ban_ip(ip);
    }

    //passed all rules
    ptr = ip_end;
  } //end rules
}



void ssh_fw(void) {
  register char *ptr = sbuff;
  char *ip;

  while(*ptr) {
    while(*ptr && *ptr != ']') //skip past datestamp to actual msg
      ptr += 1;
    ptr += 3;
    if(*ptr != 'A' && *ptr != 'R' && *ptr != 'D') { //auth fail
      while(*ptr && *ptr != '\n' && (*ptr > '9' || *ptr < '1')) //find ipv4 in current line
        ptr += 1;
      if(*ptr && *ptr != '\n' && (ptr[6] == '.' || (ptr[6] >= '0' && ptr[6] <= '9'))) { //confirm it is an ipv4
        ip = ptr;
        ptr += 7; //min ipv4 length
        while(*ptr && *ptr != ' ' && *ptr != '\n') //find end of ip str
          ptr += 1;
        ptr[1] = (*ptr == 0) ? 0 : ptr[1]; //dup null term if this is the last line, to break loop. so we can insert line term
        *ptr++ = 0; //insert line term. ip str
        if(ptr - ip < 17 && strIdent(ip, WHITELIST_SERVER_IP))
          ban_ip(ip);
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

  pthread_t nginx_thread, ssh_thread;
  pthread_create(&nginx_thread, NULL, &nginx_log, NULL);
  pthread_create(&ssh_thread, NULL, &ssh_log, NULL);

  while(1) pause();

  return 0;
}

