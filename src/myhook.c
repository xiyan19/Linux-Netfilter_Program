#define __KERNEL__
#define CONFIG_NETFILTER

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* This is the structure used to register function */
struct nf_hook_ops nfho;

/* Defined dropped IP */
//TODO:IPTables
unsigned char *drop_ip = "Defined";

/* This is the hook function */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
					   const struct net_device *in,
					   const struct net_device *out,
					   int (*okfn)(struct sk_buff *))
{
	struct sk_buff *sb = *skb;
	
	if (sb->nh.iph->saddr == drop_ip) {
		printk(KERN_INFO "Drop incoming packet from %d.%d.%d.%d\n", *drop_ip, *(drop_ip + 1), *(drop_ip + 2), *(drop_ip + 3));
		
		return NF_DROP;
	}
	else {
		
		return NF_ACCEPT;
	}
}

/* Initialisation */
int init_module()
{
	nfho.hook = hook_func;
	nfho.hook_num = NF_IP_LOCAL_IN;
	//nfho.hook_num = NF_IP_LOCAL_OUT;
	//nfho.hook_num = NF_IP_FORWARD;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_hook(&nfho);
	
	return 0;
}

/* Cleanup */
void cleanup_module()
{
	nf_unregister_hook(&nfho);
}

module_init(init_module);
module_exit(cleanup_module);

MODULE_AUTHOR("QinYan");
MODULE_DESCRIPTION("A kernel module which use netfilter hook to drop designated incoming/outgoing/forward packets.");
MODULE_LICENSE("GPL");