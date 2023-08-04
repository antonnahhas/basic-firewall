#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Network Traffic Monitor");static unsigned int nf_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct icmphdr *icmph;    __be32 src_ip, dst_ip;
    iph = ip_hdr(skb);    if (iph->protocol == IPPROTO_ICMP) {
        icmph = icmp_hdr(skb);
        src_ip = iph->saddr;
        dst_ip = iph->daddr;        // Check if the source IP is rejected (192.168.91.129 or 172.16.177.128)
        if ((src_ip != htonl(0xC0A85B81)) && (src_ip != htonl(0xAC10B180))) {
            // Log information about the dropped packet
            printk(KERN_INFO "Dropped ICMP packet from %pI4 to %pI4\n", &src_ip, &dst_ip);            // Return NF_DROP to drop the packet
            return NF_DROP;
        }
    }    return NF_ACCEPT;
}static struct nf_hook_ops nfho = {
    .hook = nf_hook_function,
    .hooknum = NF_INET_PRE_ROUTING, // Choose an appropriate hook number
    .pf = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};static int __init traffic_monitor_init(void) {
    printk(KERN_INFO "Network Traffic Monitor: Netfilter hook registered.\n");
    nf_register_net_hook(&init_net, &nfho);
    return 0;
}static void __exit traffic_monitor_exit(void) {
    printk(KERN_INFO "Network Traffic Monitor: Unregistering Netfilter hook.\n");
    nf_unregister_net_hook(&init_net, &nfho);
}module_init(traffic_monitor_init);
module_exit(traffic_monitor_exit);
