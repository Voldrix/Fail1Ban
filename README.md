# Fail1Ban
__A Linux kernel module firewall and userspace log parser and auto-banner.__

Instead of reading log files from the filesystem, this uses pipes (fifo) so _Nginx_ and _OpenSSH_ can send their logs directly into the application.

## How it works
### Kernel Module Firewall
Just write an IP address to `/proc/fail1ban` and it will be banned.\
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
__OpenSSH:__ 1 failure bans immediately.\
__Nginx:__ by default, there are 4 rules:\
HTTP status codes 400 and 444 ban immediately.\
301 and 404 issue two (silent) warnings before banning on the third attempt. Only the most recent 16 warnings are remembered.

These rules are very simple, and easy for you to add your own custom tailored to your web logs.

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
`make` will build the kernel module and the log parser. (`make mod` + `make log`)\
Install the kernel module with `modprobe ./fail1ban_mod.ko`\
Run the parser daemon `./fail1ban_log` before restarting nginx and rsyslog.

Once the named pipes have been created the first time, you can stop and restart the log daemon without restarting nginx and rsyslog. They will automatically start sending logs again.

#### License
[MIT](LICENSE)
