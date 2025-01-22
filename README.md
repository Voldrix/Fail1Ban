# Fail1Ban
__A Linux kernel module firewall and userspace log parser and auto-banner for blocking web bots.__

Instead of reading log files from the filesystem, this uses pipes (fifo) so _Nginx_ and _OpenSSH_ can send their logs directly into the application.

## How it works
### Kernel Module Firewall
Write an IPv4 address to `/proc/fail1ban` and it will be banned.\
Any application can do this, including from the shell.\
Any message not starting numerically will clear all bans.
```
echo -n 10.10.10.10 > /proc/fail1ban   #bans ip
echo clear > /proc/fail1ban            #clears all bans
```
Reading from `/proc/fail1ban` will list all currently banned IPs.
```
cat /proc/fail1ban
```
Linux can run multiple firewalls simultaneously, so you don't need to disable IPtables / etc.

### Log Parser Auto-Banner
Accepts logs directly from OpenSSH and Nginx via two named pipes (fifo), `/run/fail1ban-nginx` and `/run/fail1ban-ssh`\
__OpenSSH:__\
One failure bans immediately.\
These rules are minimized for brevity. You may need to adjust them for your version of OpenSSH.\
__Nginx:__\
By default, there are 4 rules:\
HTTP status codes 400 and 444 ban immediately.\
301 and 404 issue two (silent) warnings before banning on the third attempt. Only the most recent 16 warnings are remembered.

These rules are very simple, and easy for you to add your own custom tailored to your web logs.

## Configs
### Nginx config
Nginx can handle named pipes natively, configured the same as normal files.\
You can have multiple _access_log_  directives to get multiple log files.\
`/etc/nginx/nginx.conf`
```
log_format f1b '~$status $remote_addr#$host';
access_log /run/fail1ban-nginx f1b buffer=512 flush=50ms;
```

### OpenSSH / Rsyslod Config
OpenSSH logs to rsyslogd, and rsyslogd can handle pipes natively. Just add the pipe/bar symbol `|` before the fifo's filename.\
`/etc/rsyslog.conf`
```
auth,authpriv.*               |/run/fail1ban-ssh
```

## Build
Set whitelist IP macros for server and admin client to prevent lockout.\
`make` will build the kernel module and the log parser (`make mod` + `make log`). `make cf` for Cloudflare version.\
Install the kernel module with `modprobe ./fail1ban_mod.ko`\
Run the parser daemon `./fail1ban_log` before restarting nginx and rsyslog.

Once the named pipes have been created the first time, you can stop and restart the log daemon without restarting nginx and rsyslog. They will automatically start sending logs again.

## Cloudflare
The `fail1ban_log_cloudflare.c` log parser works with a mixture of domains both on and off of Cloudflare.

__Requirements__\
SSL relay.\
Cloudflare [list](https://developers.cloudflare.com/waf/tools/lists/custom-lists/). Block the list in the WAF.

__Setup__\
Set your SSL relay hostname (line 20)\
Whitelist your own IP address, just in case (lines 21-22)\
Rewrite lines 109 and 118 to uniquely identify domain names on Cloudflare\
Update the Cloudflare API request on line 221 with: account ID, list ID, ssl relay hostname, account email, api key

Nginx SSL relay:
```
server {
  merge_slashes off;
  set_real_ip_from 0.0.0.0/0;
  real_ip_header X-Forwarded-For;

  location ~ ^/sslrelay/(.*) {
    resolver 1.0.0.1;
    proxy_pass https://$http_x_forwarded_for/$1;
    proxy_set_header Host $http_x_forwarded_for;
    proxy_ssl_server_name on;
  }
}
```

### ToDo
- IPv6
- unban individual ip
- Generalize ssh ban triggers
- Generalize domain name separation
- CF API request failsafe
- Allow newline IP string termination

### License
[MIT](LICENSE)
