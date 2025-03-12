//must match PROCFS_NAME in fail1ban_mod.c
#define F1B_PROCFS "/proc/fail1ban"

//for both log parsers
#define NGINX_PIPE "/run/fail1ban-nginx"
#define SSH_PIPE "/run/fail1ban-ssh"
#define BUFFER_SIZE 2048
#define RECENT_WARNINGS 16 //power of 2

#define WHITELIST_SERVER_IP "0.0.0.0"
#define WHITELIST_MY_IP "0.0.0.0"

//for cloudflare log parser
#define CF_QUEUE_SIZE 64 //power of 2
#define SSL_RELAY_HOSTNAME "localhost"

#define CF_ACCOUNT_EMAIL "_@_.com"
#define CF_ACCOUNT_ID "0000"
#define CF_LIST_ID "0000"
#define CF_API_KEY "0000"

