#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include "ip_str_convert.c"

#define BANNED_IP_MAX 16 //must be power of 2, for line 97
#define PROCFS_MAX_SIZE 32
#define PROCFS_NAME "fail1ban"

static unsigned char ban_tail[256];
static unsigned int readPos, banned_ip[256][BANNED_IP_MAX];
static char procfs_buffer[PROCFS_MAX_SIZE], outBuff[18];
static struct proc_dir_entry *proc_file;
static struct nf_hook_ops hook_ops;



//FILTER HOOK
static int vs_filter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {

  struct iphdr *iph = ip_hdr(skb);
  register int ret = 0, idx = iph->saddr & 255;

  for(int i = 0; i < BANNED_IP_MAX; i++)
    ret += (iph->saddr == banned_ip[idx][i]);

  return ret ? NF_DROP : NF_ACCEPT;
}



//CLEAR BANS
static inline void clear_bans(void) {
  memset(ban_tail, 0, sizeof(ban_tail));
  memset(banned_ip, 0, sizeof(banned_ip));
}



//READ PROC
static ssize_t procfile_read(struct file *file_pointer, char __user *buffer, size_t buffer_length, loff_t *offset) {

  unsigned int len, err, written = 0;
  readPos = (*offset) ? readPos : 0; //reading first chunk?

  if(buffer_length < 16)
    return 0;

  for( ; readPos < 256; readPos++) {
    for(int pos = 0; pos < BANNED_IP_MAX; pos++) {
      if(!banned_ip[readPos][pos])
        break;
      len = ip_to_str(banned_ip[readPos][pos], outBuff);
      outBuff[len++] = '\n';
      if(len + written > buffer_length) //filled user's read buff
        return written;
      err = copy_to_user(buffer + written, outBuff, len);
      written += len - err;
      *offset = written;
    }
  }

  return written;
}



//WRITE PROC
static ssize_t procfile_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {

  //we could read in chunks, but we don't allow long msgs.
  if(len >= PROCFS_MAX_SIZE)
    return -EMSGSIZE;

  if(copy_from_user(procfs_buffer, buff, len))
    return -EFAULT;
  procfs_buffer[len] = 0; //null terminate str

  //any str not starting with 0-9 will clear all bans
  if(procfs_buffer[0] < '0' || procfs_buffer[0] > '9')
    clear_bans();
  else { //ban ip
    unsigned int ip = str_to_ip(procfs_buffer);
    unsigned int idx = ip & 255; //first octet in little-endian order
    //check if ban already exists
    register int preexisting = 0;
    for(int i = 0; i < BANNED_IP_MAX; i++)
      preexisting += (banned_ip[idx][i] == ip);
    if(!preexisting) {
      banned_ip[idx][ban_tail[idx]++] = ip; //ban ip
      ban_tail[idx] &= BANNED_IP_MAX - 1;
    }
  }

  //*off += len; //not needed since we don't allow writes larger than one buffer

  return len;
}



#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
  static const struct proc_ops proc_file_fops = { .proc_read = procfile_read, .proc_write = procfile_write };
#else
  static const struct file_operations proc_file_fops = { .read = procfile_read, .write = procfile_write, };
#endif



//INIT MOD
static int __init init_mod(void) {
  hook_ops.hook = (nf_hookfn*)vs_filter;
  hook_ops.dev = 0;
  hook_ops.priv = 0;
  hook_ops.pf = NFPROTO_IPV4;
  hook_ops.hooknum = NF_INET_LOCAL_IN;
  hook_ops.priority = 3;

  nf_register_net_hook(&init_net, &hook_ops);

  proc_file = proc_create(PROCFS_NAME, 0666, NULL, &proc_file_fops);

  if(!proc_file) {
    proc_remove(proc_file);
    return -ENOMEM;
  }

  clear_bans();

  return 0;
}



//EXIT MOD
static void __exit decommission_mod(void) {
  nf_unregister_net_hook(&init_net, &hook_ops);
  proc_remove(proc_file);
}



module_init(init_mod);
module_exit(decommission_mod);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("Voldrix");
MODULE_DESCRIPTION("Fail1Ban Firewall");

