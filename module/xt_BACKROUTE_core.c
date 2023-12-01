#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>

#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_extend.h>

#include <linux/if_arp.h>
#include <linux/netfilter_arp.h>

#include "nf_backroute.h"

// =====================================================================

#define MOD_NAME	"xt_BACKROUTE"
#define MOD_ALIAS	"ipt_BACKROUTE"

// =====================================================================

typedef union iptbckrtdt_u {
	uint64_t ar[2];
	struct {
		int			ifindex;
		uint8_t		mac[ETH_ALEN];
		union {
			uint8_t f_all;
			struct {
			uint8_t f_update:1;
			uint8_t f_hook:1;
			uint8_t f_dir:1;
			uint8_t f_init:1;
			};
		};
		uint8_t		sign[5];
	} __attribute__((packed));
	} iptbckrtdt_t;

static const char sign_iptbckrtdt[] = "bckrt";

// =====================================================================

static int get_src_mac(struct sk_buff *skb, uint8_t *mac)
{
	int ret = 0;

	if(!skb || !mac) return(-EINVAL);
	if (skb->dev == NULL || skb->dev->type != ARPHRD_ETHER) return(-EINVAL);
	if (skb_mac_header(skb) < skb->head) return(-EINVAL);
	if (skb_mac_header(skb) + ETH_HLEN > skb->data) return(-EINVAL);
	memcpy( mac, &(eth_hdr(skb)->h_source), ETH_ALEN);

	return(ret);
}

// =====================================================================

static iptbckrtdt_t * find_cte(struct nf_ct_ext *ext)
{
	iptbckrtdt_t *pi, *udt = NULL;
	unsigned int len, i;
	uint8_t *p;

	if (!ext) goto out;

	len =  ext->len;
	len -= sizeof(iptbckrtdt_t);
	p   =  ext->data;
	i   = sizeof(struct nf_ct_ext);

	while( i < len ) {
		pi = (iptbckrtdt_t*)&p[i];
		if( memcmp( pi->sign, sign_iptbckrtdt, sizeof(pi->sign) ) == 0 ) {
			udt = pi;
			break;
		}
		i += sizeof(int);
	}

out:
	return(udt);
}


static iptbckrtdt_t * crt_or_fnd_cte(struct nf_conn *ct)
{
	unsigned int len = sizeof(*(ct->ext)) + sizeof(iptbckrtdt_t);
	unsigned int oln = 0, nof = 0, alc = 0;
	struct nf_ct_ext *new;
	iptbckrtdt_t *pudt = NULL;

	if (ct->ext) {
		pudt = find_cte(ct->ext);
		if(pudt) goto out;
		oln = ct->ext->len;
	}else{
		oln = sizeof(*new);
	}

	nof = ALIGN(oln, __alignof__(struct nf_ct_ext));
	len = nof + sizeof(*pudt);
	alc = max(len, 128u);

	new = krealloc(ct->ext, alc, GFP_ATOMIC);
	if (!new)
		goto out;

	if (!ct->ext) {
		memset(new->offset, 0, sizeof(new->offset));
		//new->gen_id = atomic_read(&nf_conntrack_ext_genid);
	}

	new->len = len;
	pudt = (void*)new + nof;
	memcpy(pudt->sign, sign_iptbckrtdt, sizeof(pudt->sign));
	//memcpy((void*)new + nof, pudt, sizeof(*pudt));
	//printk("dst=%p, src=%p, sz=%ld ct->ext=%p new=%p\n",(void*)new + nof, udt, sizeof(*udt), ct->ext, new);

	ct->ext = new;
out:
	return(pudt);
}


// =====================================================================

static int xmit_skb(struct net *net, struct sk_buff *skb, int idxdev, uint8_t *dstmac)
{
	int ret = 0;
	struct net_device	*idev = NULL;
	struct sk_buff 		*nskb = NULL;

	if(!net) goto err;

	idev = dev_get_by_index(net, idxdev);
	if(!idev) goto err;

	nskb = skb_clone(skb, GFP_ATOMIC);
	if(!nskb) {
		ret = -ENOMEM;
		goto out;
	}

	nskb->dev = idev;
	ret = dev_hard_header(nskb, idev, ntohs(skb->protocol), dstmac, NULL, skb->len);

	if (ret >= 0) {
		ret = dev_queue_xmit(nskb);
		nskb = NULL;
		}

	if(ret) {
		printk("ERR: dev_queue_xmit = %d\n",ret);
		ret = -EIO;
	}

out:
	if(idev) dev_put(idev);
	if(nskb) kfree_skb(nskb);
	return(ret);
err:
	printk("ERR: net=%p idev=%p idxdev=%d\n",net, idev, idxdev);
	ret = -EINVAL;
	goto out;
}

// =====================================================================

static unsigned int backroute_output(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    )
{
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	int dir;
	struct nf_conn *ct;
	struct iphdr *iph;
	iptbckrtdt_t *pudt;

	if(!skb) goto out;

	iph = ip_hdr(skb);
	if(!iph) goto out;
	if ( skb->protocol != htons(ETH_P_IP) && 
	     skb->protocol != htons(ETH_P_IPV6) ) goto out;

	ct = nf_ct_get(skb, &ctinfo);
	if(!ct) goto out;

	dir = CTINFO2DIR(ctinfo);
	dir = (dir == IP_CT_DIR_ORIGINAL)?0:1;

	pudt = find_cte(ct->ext);
	if(!pudt || !pudt->f_init) goto out;

	if(pudt->f_dir == dir) goto out;

	switch(state->hook) {
		case NF_INET_POST_ROUTING:
			if(pudt->f_hook != hook_post) goto out;
			break;
		case NF_INET_LOCAL_OUT:
		case NF_INET_FORWARD:
			if(pudt->f_hook != hook_pre) goto out;
			break;
		default:
			goto out;
			break;
	};

	ret = xmit_skb(state->net, skb, pudt->ifindex, pudt->mac);
	if(!ret) {
		printk("TXO: skb=%p ct=%p cte=%p dIP=%08X dev=%s\n", skb, ct, ct->ext, iph->daddr, skb->dev->name);
		return NF_DROP;
	}else{
		printk("ErrTX=%d skb=%p ct=%p cte=%p dIP=%08X dev=%s\n", ret, skb, ct, ct->ext, iph->daddr, skb->dev->name);
	}

out:	
    return NF_ACCEPT;
}

// =====================================================================

static struct nf_hook_ops all_backroute_hooks[] = {
    {
        .hook		= backroute_output,
        .pf			= NFPROTO_IPV4,
        .hooknum	= NF_INET_POST_ROUTING,
        .priority	= NF_IP_PRI_LAST,
    },
    {
        .hook		= backroute_output,
        .pf			= NFPROTO_IPV4,
        .hooknum	= NF_INET_LOCAL_OUT,
        .priority	= NF_IP_PRI_LAST,
    },
    {
        .hook		= backroute_output,
        .pf			= NFPROTO_IPV4,
        .hooknum	= NF_INET_FORWARD,
        .priority	= NF_IP_PRI_LAST,
    },
};
static const unsigned int all_backroute_hooks_num = ARRAY_SIZE(all_backroute_hooks);

// =====================================================================

static unsigned int backroute_tg_v4(struct sk_buff *skb, const struct xt_action_param *par)
{
	unsigned ret = 0;
	const nf_backroute_t *opt = par->targinfo;
	struct nf_conn *ct;
	iptbckrtdt_t *pudt = NULL;
	enum ip_conntrack_info ctinfo;
	int dir;
	int  ifindex = -1;
	uint8_t	mac[ETH_ALEN];

	if(!skb && !skb->dev) goto out;

	ct = nf_ct_get(skb, &ctinfo);
	if(!ct) goto out; // Возможно не загружен модуль conntrack

	dir = CTINFO2DIR(ctinfo);
	dir = (dir == IP_CT_DIR_ORIGINAL)?0:1;
	//if(ctinfo == IP_CT_NEW)

	pudt = crt_or_fnd_cte(ct);
	if(!pudt) goto out; // что-то полшло не так.

	ifindex = skb->dev->ifindex;

	ret = get_src_mac(skb, mac);
	if(ret) goto out;

	if(	pudt->f_init &&
		!pudt->f_update &&
		!opt->f_update )
		goto out;

	if( pudt->f_init && pudt->f_dir != dir )
		goto out;

	/* Обновление данных в cte */
	pudt->f_update	= ((opt->f_update==2)?1:0); // always ?
	pudt->f_hook	= opt->f_hook;
	pudt->f_dir		= dir;
	pudt->ifindex	= ifindex;
	memcpy(pudt->mac, mac, sizeof(pudt->mac));
	pudt->f_init	= 1;
printk("backroute_tg_v4 upd = OK\n");
out:
	return(NF_ACCEPT);
}


static int backroute_tg_check(const struct xt_tgchk_param *par)
{
	int ret = 0;
	const nf_backroute_t *opt = par->targinfo;
	nf_backroute_t tmp = *opt;

	tmp.f_update = 0;
	tmp.f_hook = 0;
	if(tmp.all) {
		return(-EINVAL);
	}

	ret = nf_ct_netns_get(par->net, par->family);

	return(ret);
}


static void backroute_tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

// =====================================================================

static struct xt_target backroute_tg_reg[] __read_mostly = {
	{
	.name		= TARGET_NAME,
	.family		= NFPROTO_IPV4,
	.revision   = 0,
	.table      = "mangle",
	.target		= backroute_tg_v4,
	.targetsize	= sizeof(nf_backroute_t),
	.usersize	= sizeof(nf_backroute_t),
	.hooks		= 1 << NF_INET_PRE_ROUTING,
	.checkentry	= backroute_tg_check,
	.destroy	= backroute_tg_destroy,
	.me			= THIS_MODULE,
	},
};

static const unsigned int backroute_tg_reg_num = ARRAY_SIZE(backroute_tg_reg);

// =====================================================================

static int __init nf_module_init(void)
{
	int ret = 0;

	BUILD_BUG_ON( sizeof(iptbckrtdt_t) > 16 );

	printk(KERN_INFO MOD_NAME " module initialized.\n");
	ret = nf_register_net_hooks(&init_net, all_backroute_hooks, all_backroute_hooks_num);
	if (ret < 0) {
		printk(KERN_INFO MOD_NAME " - Failed to register hook\n");
		goto out;
	} else {
		printk(KERN_INFO MOD_NAME " - OK to register hook\n");
	}

	ret = xt_register_targets(backroute_tg_reg, backroute_tg_reg_num);
	if(ret) {
		printk(KERN_INFO MOD_NAME " xt_register_targets = %d\n",ret);
		nf_unregister_net_hooks(&init_net, all_backroute_hooks, all_backroute_hooks_num);
	}else{
		printk(KERN_INFO MOD_NAME " - OK to register targets\n");
	}

out:
	return ret;
}


static void __exit nf_module_exit(void)
{
	printk(KERN_INFO MOD_NAME " module exit.\n");
	nf_unregister_net_hooks(&init_net, all_backroute_hooks, all_backroute_hooks_num);
	xt_unregister_targets(backroute_tg_reg, backroute_tg_reg_num);
}

// =====================================================================

module_init(nf_module_init);
module_exit(nf_module_exit);

// =====================================================================

MODULE_AUTHOR("dsn");
MODULE_DESCRIPTION("Xtables: netfilter module " MOD_NAME);
MODULE_LICENSE("GPL");
//MODULE_ALIAS(MOD_NAME);
MODULE_ALIAS(MOD_ALIAS);
MODULE_SOFTDEP("pre: xt_conntrack");
MODULE_SOFTDEP("pre: nf_conntrack");

// =====================================================================

