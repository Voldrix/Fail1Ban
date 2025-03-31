//for kernel module
#define BANNED_IP_MAX 16 //per A block (256x this value total). power of 2
#define PROCFS_MAX_SIZE 32
#define PROCFS_NAME "fail1ban"

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

#define CF_NUM_HOSTS 2
#define CF_HOSTS {"example.com", "example.org"}

