/*
 * The kernel module.
 * Use kbuild to compile.Change protocal in line 31.Change port in line 33.Change hook type in line 59.
 *
 * Last modified by Qinyan on 7/10/15.
 * Email:qq416206@gmail.com
 *
 * Created by QinYan on 7/9/15.
 * Email:qq416206@gmail.com
 */

#include <linux/module.h>

/* This is the structure used to register function */
struct nf_hook_ops nfho;

/* This is the hook function */
static unsigned int hook_func(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = ip_hdr(skb);
    tcph = (void *)iph+iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP)
    {
        if (tcph->dest == htons(8080) || tcph->dest == htons(80))
        {
            printk(KERN_INFO "Push packet from %d.%d.%d.%d\n", ((unsigned char *)&iph->saddr)[0],
                                                               ((unsigned char *)&iph->saddr)[1],
                                                               ((unsigned char *)&iph->saddr)[2],
                                                               ((unsigned char *)&iph->saddr)[3]);

            return NF_QUEUE;
        }
        else
        {
            return NF_ACCEPT;
        }
    }
    else
    {
        return NF_ACCEPT;
    }
}

/* Initialisation */
int init_module(void)
{
    printk(KERN_INFO "-----My Netfilter Kernel Module Start-----");

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;  //nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
	
    nf_register_hook(&nfho);
	
    return 0;
}

/* Cleanup */
void cleanup_module(void)
{
    printk(KERN_INFO "-----My Netfilter Kernel Module Stop-----");

    nf_unregister_hook(&nfho);
}

MODULE_AUTHOR("QinYan");
MODULE_DESCRIPTION("A kernel module which use netfilter hook to get designated incoming/outgoing HTTP packets.");
MODULE_LICENSE("GPL");