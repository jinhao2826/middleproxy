#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <net/ip.h>

static struct nf_hook_ops nfho;

unsigned int ip_str_to_num(const char *buf)

{

    unsigned int tmpip[4] = {0};

    unsigned int tmpip32 = 0;

 

    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

    tmpip32 = (tmpip[3]<<24) | (tmpip[2]<<16) | (tmpip[1]<<8) | tmpip[0];

    return tmpip32;

}


/*function to be called by hook*/
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	char middlebox_ip[15] = "192.168.200.61";
	char redirect_ip[15] = "192.168.30.108";
	struct iphdr *iph = NULL;
	struct tcphdr *tcph=NULL;
	int tcplen;
	unsigned int middlebox_networkip;
	unsigned int redirect_networkip;

	iph = ip_hdr(skb);

	middlebox_networkip = ip_str_to_num(middlebox_ip);
	//printk(KERN_INFO "middlebox network IP=%u\n", middlebox_networkip);

	redirect_networkip = ip_str_to_num(redirect_ip);
        //printk(KERN_INFO "redirect network IP=%u\n", redirect_networkip);

        if(iph->protocol == IPPROTO_TCP)
	{
		//printk(KERN_INFO "ip dest IP=%u\n", iph->daddr);
		tcph = (struct tcphdr *)((__u32 *)iph+ iph->ihl);
		
		
//		tcplen = (skb->len - (iph->ihl << 2));

		tcplen = skb->len - ip_hdrlen(skb);

		printk(KERN_INFO "destIP:%u   srcIP:%u    dest port:%u     src port:%u\n", iph->daddr, iph->saddr, tcph->dest, tcph->source); 		
	
		if(iph->daddr == middlebox_networkip && tcph->dest == 38182)
		{
			
			iph->daddr = redirect_networkip;
		//	iph->daddr = middlebox_networkip;
			iph->tos = 0xe0;
			printk(KERN_INFO "modify the dest ip to redirectip\n");
			//iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
//			ip_send_check(iph);
			tcph->check = 0; 
			//tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));
			tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcplen, 0));

			skb->ip_summed = CHECKSUM_NONE;
			ip_send_check(iph);
		}
	/*	
		if(iph->saddr == redirect_networkip && tcph->source == 38182)
		{
			iph->saddr = middlebox_networkip;
			printk(KERN_INFO "modify the src ip to middleboxip\n");
			ip_send_check(iph);
			tcph->check = 0;
			tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(tcph, tcph->doff << 2, skb->csum));

		
		
		}
	*/
 	}
	
//	printk(KERN_INFO "%lu\n", jiffies);                                             //log to var/log/syslog
	return NF_ACCEPT;                                                              
}

/*Called when module loaded using insmod*/
int init_module()
{
	nfho.hook = hook_func;                   
	nfho.hooknum = NF_INET_PRE_ROUTING;   
//	nfho.hooknum = 1;      
	nfho.pf = PF_INET;                           
	nfho.priority = NF_IP_PRI_FIRST;             
	nf_register_hook(&nfho);                     
	return 0;                                    
}


/*Called when module unloaded using rmmod*/
void cleanup_module()
{
  	nf_unregister_hook(&nfho);                   
}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("HaoJIN");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("middlepolice");
