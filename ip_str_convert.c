//STR to IP (little-endian)
static unsigned int str_to_ip(char *str) {
  register unsigned int ip, octet;
  register char *tail = str;
  while(*tail++)
    ;
  tail -= 2;

  octet = *tail-- - '0';
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 10;
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 100;
  tail -= 1;
  ip = octet << 24;
  octet = *tail-- - '0';
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 10;
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 100;
  tail -= 1;
  ip |= octet << 16;
  octet = *tail-- - '0';
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 10;
  octet += (*tail == '.') ? 0 : (*tail-- - '0') * 100;
  tail -= 1;
  ip |= octet << 8;
  octet = *tail-- - '0';
  octet += (tail < str) ? 0 : (*tail-- - '0') * 10;
  octet += (tail < str) ? 0 : (*tail - '0') * 100;
  ip |= octet;

  return ip;
}



//IP (little-endian) to STR
static unsigned int ip_to_str(unsigned int ip, unsigned char* buff) {
  register unsigned char *tail = buff, tmp;
  register unsigned int n, num, count = 0;
  unsigned char octet[4];
  octet[0] = ip >> 24;
  octet[1] = (ip >> 16) & 255;
  octet[2] = (ip >> 8) & 255;
  octet[3] = ip & 255;

  for(int i = 0; i < 4; i++) {
    num = octet[i];
    *tail = '0';
    tail += !num;
    count += !num;
    while(num > 0) {
      n = num % 10;
      num /= 10;
      *tail++ = n + '0';
      count += 1;
    }
    *tail++ = '.';
  }
  count += 3;
  tail -= 1;
  *tail-- = 0;

  while(buff < tail) {
    tmp = *buff;
    *buff++ = *tail;
    *tail-- = tmp;
  }

  return count;
}

