#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <net/ip.h>
#include <net/dst.h>

MODULE_LICENSE("GPL");

static unsigned int mark = 0;
module_param(mark, uint, 0400);
MODULE_PARM_DESC(mark, "mark that needs to be converted");

static unsigned int
ipv4_pseudotcp_hook(void *priv,
		    struct sk_buff *skb,
		    const struct nf_hook_state *state)
{
	struct iphdr *iph = ip_hdr(skb), ihdr;
	struct tcphdr *tcph, thdr;
	struct udphdr *udph, uhdr;
        __be16 *psport, *pdport;
	__be16 oldlen = 0;
	char *start = (char *)iph + iph->ihl*4;
	unsigned int delta = sizeof(struct tcphdr) - sizeof(struct udphdr);
	static unsigned int seq = 8934678;

	if (skb->mark == 0 || skb->mark != mark)
		goto out;

	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
		goto out;

	// source
	psport = (__be16 *)start;
	// dest
	pdport = psport + 1;
	udph = (struct udphdr *)start;
	tcph = (struct tcphdr *)start;
	ihdr = *iph;
	thdr = *tcph;
	uhdr = *udph;

	if (iph->protocol == IPPROTO_TCP && state->hook == NF_INET_PRE_ROUTING) {
		ihdr.protocol = IPPROTO_UDP;
		oldlen = ntohs(ihdr.tot_len);
		ihdr.tot_len = htons(oldlen - delta);

		iph = (struct iphdr *)skb_pull(skb, delta);
		*iph = ihdr;

		skb_reset_network_header(skb);
		skb_set_transport_header(skb,  iph->ihl*4);

		ip_send_check(iph);

		udph = (struct udphdr *)skb_transport_header(skb);
		udph->source = thdr.source;
		udph->dest = thdr.dest;
		udph->len = htons(ntohs(iph->tot_len) - sizeof(struct iphdr));
		udph->check = 0;
	} else if (iph->protocol == IPPROTO_UDP && state->hook == NF_INET_POST_ROUTING) {
		struct dst_entry *dst = NULL;

		ihdr.protocol = IPPROTO_TCP;
    // 打散IPID？打散TOS？避免深度探测IPID分布，避免被GRO/LRO？？？
		oldlen = ntohs(ihdr.tot_len);
		ihdr.tot_len = htons(oldlen + delta);

		if ((dst = skb_dst(skb)) == NULL)
			goto out;

		if (oldlen + delta +  LL_RESERVED_SPACE(dst->dev) > dst_mtu(dst))
			goto out;

		if (pskb_expand_head(skb, delta, 0, GFP_ATOMIC))
			goto out;

		iph = (struct iphdr *)skb_push(skb, delta);
		*iph = ihdr;

		skb_reset_network_header(skb);
		skb_set_transport_header(skb, iph->ihl*4);

		ip_send_check(iph);

		tcph = (struct tcphdr *)skb_transport_header(skb);
		tcph->source = uhdr.source;
		tcph->dest = uhdr.dest;
		tcph->seq = htonl(seq);
		seq += 1000;
		tcph->ack_seq = 8910;
		tcph->syn = 0;
		tcph->doff = 5;
		tcph->ack = 1;
		tcph->urg = 1;
		tcph->rst = 0;
		tcph->fin = 0;
		tcph->window = htons(1000);
	}

out:
	return NF_ACCEPT;
}

static const struct nf_hook_ops ipv4_pseudotcp_ops[] = {
	{
		.hook		= ipv4_pseudotcp_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= ipv4_pseudotcp_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_RAW + 1,
	},
};

static int __init pseudotcp_init(void)
{
	int ret;

	ret = nf_register_net_hooks(&init_net, ipv4_pseudotcp_ops,
					ARRAY_SIZE(ipv4_pseudotcp_ops));
	if (ret) {
		printk("[ipv4_pseudotcp] register failed!\n");
		return ret;
	}

	printk("[ipv4_pseudotcp] welcome !\n");

	return ret;
}


static void __exit pseudotcp_exit(void)
{
	nf_unregister_net_hooks(&init_net, ipv4_pseudotcp_ops,
					ARRAY_SIZE(ipv4_pseudotcp_ops));
	printk("[ipv4_pseudotcp] bye ...\n");
}

module_init(pseudotcp_init);
module_exit(pseudotcp_exit);
