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
#define RECENT_WARNINGS 16 //power of 2 (for line 43)

int f1b_procfs, warning_tail = 0;
char nbuff[BUFFER_SIZE];
char sbuff[BUFFER_SIZE];
unsigned int warnings[RECENT_WARNINGS];



void ban_ip(char *ip) {
  write(f1b_procfs, ip, 15);
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

  return (warn == 2); //ban if 2 warning exist
}



void nginx_fw(void) {
  char *ip, *ip_end, *ptr = nbuff;

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

    //rule 444 && rule 400
    if(ptr[2] == '4' || (ptr[1] == '4' && ptr[3] == '0')) {
      ban_ip(ip);
    }

    //rule 404
    if(ptr[1] == '4' && ptr[3] == '4') {
      if(warning_check(ip))
        ban_ip(ip);
    }

    //rule 301
    if(ptr[1] == '3' && ptr[3] == '1') {
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
    while(*ptr != ']') //skip past datestamp to actual msg
      ptr += 1;
    ptr += 3;
    if(*ptr != 'A' && *ptr != 'R' && *ptr != 'D') { //auth fail
      while(*ptr && *ptr != '\n' && (*ptr > '9' || *ptr < '1')) //find ipv4 in current line
        ptr += 1;
      if(*ptr && *ptr != '\n' && (ptr[6] == '.' || (ptr[6] >= '0' && ptr[6] <= '9'))) { //confirm it is an ipv4
        ip = ptr;
        ptr += 7; //min ipv4 length
        while(*ptr && *ptr != ' ' && *ptr != '\n')
          ptr += 1;
        *ptr++ = 0; //null term ip str
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

  f1b_procfs = open(F1B_PROCFS, O_WRONLY);
  if(f1b_procfs < 1)
    return 1;

  pthread_t nginx_thread;
  pthread_create(&nginx_thread, NULL, &nginx_log, NULL);
  pthread_t ssh_thread;
  pthread_create(&ssh_thread, NULL, &ssh_log, NULL);

  while(1) pause();

  return 0;
}

