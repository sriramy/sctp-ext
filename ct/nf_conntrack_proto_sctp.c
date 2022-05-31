// SPDX-License-Identifier: GPL-2.0-only
/*
 * Connection tracking protocol helper module for SCTP.
 *
 * Copyright (c) 2004 Kiran Kumar Immidi <immidi_kiran@yahoo.com>
 * Copyright (c) 2004-2012 Patrick McHardy <kaber@trash.net>
 *
 * SCTP is defined in RFC 4960. References to various sections in this code
 * are to this RFC.
 */

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/netfilter.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <net/sctp/checksum.h>

#include <net/netfilter/nf_log.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_timeout.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>

static const char *const sctp_conntrack_names[] = {
	"NONE",
	"CLOSED",
	"COOKIE_WAIT",
	"COOKIE_ECHOED",
	"ESTABLISHED",
	"SHUTDOWN_SENT",
	"SHUTDOWN_RECD",
	"SHUTDOWN_ACK_SENT",
	"HEARTBEAT_SENT",
	"HEARTBEAT_ACKED",
};

#define SECS  * HZ
#define MINS  * 60 SECS
#define HOURS * 60 MINS
#define DAYS  * 24 HOURS

static const unsigned int sctp_timeouts[SCTP_CONNTRACK_MAX] = {
	[SCTP_CONNTRACK_CLOSED]			= 10 SECS,
	[SCTP_CONNTRACK_COOKIE_WAIT]		= 3 SECS,
	[SCTP_CONNTRACK_COOKIE_ECHOED]		= 3 SECS,
	[SCTP_CONNTRACK_ESTABLISHED]		= 5 DAYS,
	[SCTP_CONNTRACK_SHUTDOWN_SENT]		= 300 SECS / 1000,
	[SCTP_CONNTRACK_SHUTDOWN_RECD]		= 300 SECS / 1000,
	[SCTP_CONNTRACK_SHUTDOWN_ACK_SENT]	= 3 SECS,
	[SCTP_CONNTRACK_HEARTBEAT_SENT]		= 10 SECS,
	[SCTP_CONNTRACK_HEARTBEAT_ACKED]	= 210 SECS,
};

#ifdef CONFIG_NF_CONNTRACK_PROCFS
/* Print out the private part of the conntrack. */
static void sctp_print_conntrack(struct seq_file *s, struct nf_conn *ct)
{
	seq_printf(s, "%s ", sctp_conntrack_names[ct->proto.sctp.state]);
}
#endif

static int ipv4_get_l4proto(const struct sk_buff *skb, unsigned int nhoff,
			    u_int8_t *protonum)
{
	int dataoff = -1;
	const struct iphdr *iph;
	struct iphdr _iph;

	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (!iph)
		return -1;

	/* Conntrack defragments packets, we might still see fragments
	 * inside ICMP packets though.
	 */
	if (iph->frag_off & htons(IP_OFFSET))
		return -1;

	dataoff = nhoff + (iph->ihl << 2);
	*protonum = iph->protocol;

	/* Check bogus IP headers */
	if (dataoff > skb->len) {
		pr_debug("bogus IPv4 packet: nhoff %u, ihl %u, skblen %u\n",
			 nhoff, iph->ihl << 2, skb->len);
		return -1;
	}
	return dataoff;
}

#if IS_ENABLED(CONFIG_IPV6)
static int ipv6_get_l4proto(const struct sk_buff *skb, unsigned int nhoff,
			    u8 *protonum)
{
	int protoff = -1;
	unsigned int extoff = nhoff + sizeof(struct ipv6hdr);
	__be16 frag_off;
	u8 nexthdr;

	if (skb_copy_bits(skb, nhoff + offsetof(struct ipv6hdr, nexthdr),
			  &nexthdr, sizeof(nexthdr)) != 0) {
		pr_debug("can't get nexthdr\n");
		return -1;
	}
	protoff = ipv6_skip_exthdr(skb, extoff, &nexthdr, &frag_off);
	/*
	 * (protoff == skb->len) means the packet has not data, just
	 * IPv6 and possibly extensions headers, but it is tracked anyway
	 */
	if (protoff < 0 || (frag_off & htons(~0x7)) != 0) {
		pr_debug("can't find proto in pkt\n");
		return -1;
	}

	*protonum = nexthdr;
	return protoff;
}
#endif

static int get_l4proto(const struct sk_buff *skb,
		       unsigned int nhoff, u8 pf, u8 *l4num)
{
	switch (pf) {
	case NFPROTO_IPV4:
		return ipv4_get_l4proto(skb, nhoff, l4num);
#if IS_ENABLED(CONFIG_IPV6)
	case NFPROTO_IPV6:
		return ipv6_get_l4proto(skb, nhoff, l4num);
#endif
	default:
		*l4num = 0;
		break;
	}
	return -1;
}

static bool sctp_error(struct sk_buff *skb,
		       unsigned int dataoff,
		       const struct nf_hook_state *state)
{
	const struct sctphdr *sh;
	const char *logmsg;

	if (skb->len < dataoff + sizeof(struct sctphdr)) {
		logmsg = "nf_ct_sctp: short packet ";
		goto out_invalid;
	}
	if (state->hook == NF_INET_PRE_ROUTING &&
	    state->net->ct.sysctl_checksum &&
	    skb->ip_summed == CHECKSUM_NONE) {
		if (skb_ensure_writable(skb, dataoff + sizeof(*sh))) {
			logmsg = "nf_ct_sctp: failed to read header ";
			goto out_invalid;
		}
		sh = (const struct sctphdr *)(skb->data + dataoff);
		if (sh->checksum != sctp_compute_cksum(skb, dataoff)) {
			logmsg = "nf_ct_sctp: bad CRC ";
			goto out_invalid;
		}
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	return false;
out_invalid:
	nf_l4proto_log_invalid(skb, state, IPPROTO_SCTP, "%s", logmsg);
	return true;
}

static bool contains_init_rj(struct sk_buff *skb, unsigned int dataoff, const struct nf_hook_state *state) {
	unsigned int has_init_rj = 0;
	const struct sctp_chunkhdr *sch;
	struct sctp_chunkhdr _sch;
	unsigned int sch_len;
	struct sctp_inithdr *inith;
	struct sctp_paramhdr *param;

	sch = skb_header_pointer(skb, dataoff + sizeof(struct sctphdr), sizeof(_sch), &_sch);
	sch_len = be16_to_cpu(sch->length);
	inith = (struct sctp_inithdr*)((void*)sch + sizeof(struct sctp_chunkhdr));

	pr_debug("nf_ct_sctp: init chunk len: %u\n", sch_len);

	for (param = (struct sctp_paramhdr*)inith->params;
			((void*)param <= ((void*)sch + sch_len) - sizeof(struct sctp_paramhdr)) &&
			((void*)param <= ((void*)sch + sch_len) - be16_to_cpu(param->length)) &&
			be16_to_cpu(param->length) >= sizeof(struct sctp_paramhdr);
			param = ((void*)param + SCTP_PAD4(be16_to_cpu(param->length)))) {
		pr_debug("nf_ct_sctp: init param: %x, len: %u, padded len: %u \n",
				be16_to_cpu(param->type),
				be16_to_cpu(param->length),
				SCTP_PAD4(be16_to_cpu(param->length)));
		if (param->type == SCTP_PARAM_RJ) {
			has_init_rj = 1;
			pr_debug("nf_ct_sctp: init rj param found\n");
			break;
		}
	}

	return has_init_rj;
}

/* Returns verdict for packet, or -NF_ACCEPT for invalid. */
int nf_conntrack_sctp_packet(struct nf_conn *ct,
			     struct sk_buff *skb,
			     unsigned int dataoff,
			     enum ip_conntrack_info ctinfo,
			     const struct nf_hook_state *state)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	unsigned int *timeouts;
	unsigned int hb_interval;
	unsigned int is_init = 0;
	const struct sctphdr *sh;
	struct sctphdr _sctph;

	unsigned int ignore = 0;

	if (sctp_error(skb, dataoff, state))
		goto out;

	sh = skb_header_pointer(skb, dataoff, sizeof(_sctph), &_sctph);
	if (sh == NULL)
		goto out;

	/* if vtag is zero, assume it is an INIT chunk, and an INIT
	 * MUST be the only chunk in the SCTP packet carrying it */
	is_init = (sh->vtag == 0);
	if (is_init && !nf_sctp_pernet(nf_ct_net(ct))->discard_init) {
		goto out_drop;
	}

	/* always accept abort/init-ack(rj) with m bit set */
	if (ctinfo == IP_CT_RELATED || ctinfo == IP_CT_RELATED_REPLY) {
		pr_debug("nf_ct_sctp: related ct (abort/init-ack)");
		return NF_ACCEPT;
	}

	if (!nf_ct_is_confirmed(ct)) {
		pr_debug("nf_ct_sctp: unconfirmed ct\n");

		memset(&ct->proto.sctp, 0, sizeof(ct->proto.sctp));
		ct->proto.sctp.state = SCTP_CONNTRACK_ESTABLISHED;
		nf_conntrack_event_cache(IPCT_PROTOINFO, ct);
	} else {
		/* don't renew timeout on init retransmit so
		* port reuse by client or NAT middlebox cannot
		* keep entry alive indefinitely (incl. nat info).
		*/
		if (is_init)
			ignore = 1;
	}

	/* update last seen direction */
	/* just here as a reminder to lock if updating ct, remove!!! */
	spin_lock_bh(&ct->lock);
	ct->proto.sctp.last_dir = dir;
	spin_unlock_bh(&ct->lock);

	/* allow but do not refresh timeout */
	if (ignore)
		return NF_ACCEPT;

	timeouts = nf_ct_timeout_lookup(ct);
	if (!timeouts)
		timeouts = nf_sctp_pernet(nf_ct_net(ct))->timeouts;

	hb_interval = timeouts[SCTP_CONNTRACK_HEARTBEAT_SENT];
	nf_ct_refresh_acct(ct, ctinfo, skb, 3 * hb_interval);

	if (dir == IP_CT_DIR_REPLY &&
		!(test_bit(IPS_ASSURED_BIT, &ct->status))) {
		  set_bit(IPS_ASSURED_BIT, &ct->status);
		  nf_conntrack_event_cache(IPCT_ASSURED, ct);
	}

	return NF_ACCEPT;

out_drop:
	return -NF_DROP;

out:
	return -NF_ACCEPT;
}

static int sctp_on_clash(struct sk_buff *skb, const struct nf_conn *ct,
		struct nf_conn *loser_ct, enum ip_conntrack_info ctinfo)
{
	enum ip_conntrack_dir dir = CTINFO2DIR(ctinfo);
	int ret;

	pr_debug("nf_ct_sctp: clash, sending abort\n");
	if ((ct->status & IPS_DST_NAT_DONE) != 0) {
		ret = nf_nat_reverse_manip_pkt(skb, loser_ct, NF_NAT_MANIP_DST, dir);
		if (ret != NF_ACCEPT)
			goto drop;
	}

	if ((ct->status & IPS_SRC_NAT_DONE) != 0) {
		ret = nf_nat_reverse_manip_pkt(skb, loser_ct, NF_NAT_MANIP_SRC, dir);
		if (ret != NF_ACCEPT)
			goto drop;
	}

	if ((ct->status & IPS_NAT_DONE_MASK) != 0)
		nf_send_abort(nf_ct_net(loser_ct), skb->sk, skb, NF_INET_PRE_ROUTING);

drop:
	return NF_DROP;
}

#if IS_ENABLED(CONFIG_NF_CT_NETLINK)

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int sctp_to_nlattr(struct sk_buff *skb, struct nlattr *nla,
			  struct nf_conn *ct, bool destroy)
{
	struct nlattr *nest_parms;

	spin_lock_bh(&ct->lock);
	nest_parms = nla_nest_start(skb, CTA_PROTOINFO_SCTP);
	if (!nest_parms)
		goto nla_put_failure;

	if (nla_put_u8(skb, CTA_PROTOINFO_SCTP_STATE, ct->proto.sctp.state))
		goto nla_put_failure;

	if (destroy)
		goto skip_state;

skip_state:
	spin_unlock_bh(&ct->lock);
	nla_nest_end(skb, nest_parms);

	return 0;

nla_put_failure:
	spin_unlock_bh(&ct->lock);
	return -1;
}

static const struct nla_policy sctp_nla_policy[CTA_PROTOINFO_SCTP_MAX+1] = {
	[CTA_PROTOINFO_SCTP_STATE]	    = { .type = NLA_U8 },
};

#define SCTP_NLATTR_SIZE ( \
		NLA_ALIGN(NLA_HDRLEN + 1) + \
		NLA_ALIGN(NLA_HDRLEN + 4) + \
		NLA_ALIGN(NLA_HDRLEN + 4))

static int nlattr_to_sctp(struct nlattr *cda[], struct nf_conn *ct)
{
	struct nlattr *attr = cda[CTA_PROTOINFO_SCTP];
	struct nlattr *tb[CTA_PROTOINFO_SCTP_MAX+1];
	int err;

	/* updates may not contain the internal protocol info, skip parsing */
	if (!attr)
		return 0;

	err = nla_parse_nested_deprecated(tb, CTA_PROTOINFO_SCTP_MAX, attr,
					  sctp_nla_policy, NULL);
	if (err < 0)
		return err;

	if (!tb[CTA_PROTOINFO_SCTP_STATE])
		return -EINVAL;

	spin_lock_bh(&ct->lock);
	ct->proto.sctp.state = nla_get_u8(tb[CTA_PROTOINFO_SCTP_STATE]);
	spin_unlock_bh(&ct->lock);

	return 0;
}
#endif

#ifdef CONFIG_NF_CONNTRACK_TIMEOUT

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>

static int sctp_timeout_nlattr_to_obj(struct nlattr *tb[],
				      struct net *net, void *data)
{
	unsigned int *timeouts = data;
	struct nf_sctp_net *sn = nf_sctp_pernet(net);
	int i;

	if (!timeouts)
		timeouts = sn->timeouts;

	/* set default SCTP timeouts. */
	for (i=0; i<SCTP_CONNTRACK_MAX; i++)
		timeouts[i] = sn->timeouts[i];

	/* there's a 1:1 mapping between attributes and protocol states. */
	for (i=CTA_TIMEOUT_SCTP_UNSPEC+1; i<CTA_TIMEOUT_SCTP_MAX+1; i++) {
		if (tb[i]) {
			timeouts[i] = ntohl(nla_get_be32(tb[i])) * HZ;
		}
	}

	timeouts[CTA_TIMEOUT_SCTP_UNSPEC] = timeouts[CTA_TIMEOUT_SCTP_CLOSED];
	return 0;
}

static int
sctp_timeout_obj_to_nlattr(struct sk_buff *skb, const void *data)
{
        const unsigned int *timeouts = data;
	int i;

	for (i=CTA_TIMEOUT_SCTP_UNSPEC+1; i<CTA_TIMEOUT_SCTP_MAX+1; i++) {
	        if (nla_put_be32(skb, i, htonl(timeouts[i] / HZ)))
			goto nla_put_failure;
	}
        return 0;

nla_put_failure:
        return -ENOSPC;
}

static const struct nla_policy
sctp_timeout_nla_policy[CTA_TIMEOUT_SCTP_MAX+1] = {
	[CTA_TIMEOUT_SCTP_CLOSED]		= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_COOKIE_WAIT]		= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_COOKIE_ECHOED]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_ESTABLISHED]		= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_SHUTDOWN_SENT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_SHUTDOWN_RECD]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_SHUTDOWN_ACK_SENT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_HEARTBEAT_SENT]	= { .type = NLA_U32 },
	[CTA_TIMEOUT_SCTP_HEARTBEAT_ACKED]	= { .type = NLA_U32 },
};
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */

static unsigned int ipv4_sctpnat_hook(void *priv,
					 struct sk_buff *skb,
					 const struct nf_hook_state *state)
{
	const struct sctphdr *sh;
	struct sctphdr _sctph;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	int dataoff;
	u_int8_t protonum;
	enum ip_conntrack_dir dir;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || (NF_CT_STATE_BIT(ctinfo) == IP_CT_RELATED))
		goto out;

 	dir = CTINFO2DIR(ctinfo);

	dataoff = get_l4proto(skb, skb_network_offset(skb), state->pf, &protonum);
	if (dataoff <= 0)
		goto out_drop;

	if (protonum != IPPROTO_SCTP)
		goto out;

	sh = skb_header_pointer(skb, dataoff, sizeof(_sctph), &_sctph);
	if (sh == NULL)
		goto out_drop;

	/* if vtag is zero, assume it is an INIT chunk, and an INIT
	 * MUST be the only chunk in the SCTP packet carrying it */
	if (sh->vtag == 0) {
		if (contains_init_rj(skb, dataoff, state)) {
			pr_debug("nf_ct_sctp: send init ack rj\n");
			if ((ct->status & IPS_DST_NAT) != 0)
				nf_nat_reverse_manip_pkt(skb, ct, NF_NAT_MANIP_DST, dir);
			if ((ct->status & IPS_SRC_NAT) != 0)
				nf_nat_reverse_manip_pkt(skb, ct, NF_NAT_MANIP_SRC, dir);
			if ((ct->status & IPS_NAT_DONE_MASK) != 0) {
				nf_send_init_ack(nf_ct_net(ct), skb->sk, skb, state->hook);
				/* setup ct entry, but silently discard */
				goto out_drop;
			}
		}
	}

out:
	return NF_ACCEPT;

out_drop:
	return NF_DROP;
}

static const struct nf_hook_ops ipv4_sctpnat_ops[] = {
	{
		.hook		= ipv4_sctpnat_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_IN,
		.priority	= NF_IP_PRI_LAST,
	},
	{
		.hook		= ipv4_sctpnat_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_LAST,
	},
};

static void delayed_init_timer_handler(struct timer_list *t)
{
	struct nf_sctp_net *sn = container_of(t, struct nf_sctp_net, delayed_init);
	pr_debug("nf_ct_sctp: delay init timer expires(net=0x%p)\n", sn);
	sn->discard_init = 1;
}

void nf_conntrack_sctp_init_net(struct net *net)
{
	struct nf_sctp_net *sn = nf_sctp_pernet(net);
	unsigned int hb_interval;
	int i;

	for (i = 0; i < SCTP_CONNTRACK_MAX; i++)
		sn->timeouts[i] = sctp_timeouts[i];

	/* timeouts[0] is unused, init it so ->timeouts[0] contains
	 * 'new' timeout, like udp or icmp.
	 */
	sn->timeouts[0] = sctp_timeouts[SCTP_CONNTRACK_CLOSED];

	hb_interval = sn->timeouts[SCTP_CONNTRACK_HEARTBEAT_SENT];

	timer_setup(&sn->delayed_init, delayed_init_timer_handler, 0);
	mod_timer(&sn->delayed_init, (jiffies + 4 * hb_interval));
	sn->discard_init = 0;

	nf_register_net_hooks(net, ipv4_sctpnat_ops,
						  ARRAY_SIZE(ipv4_sctpnat_ops));
}

void nf_conntrack_sctp_fini_net(struct net *net)
{
	nf_unregister_net_hooks(net, ipv4_sctpnat_ops,
				ARRAY_SIZE(ipv4_sctpnat_ops));
}

const struct nf_conntrack_l4proto nf_conntrack_l4proto_sctp = {
	.l4proto 		= IPPROTO_SCTP,
#ifdef CONFIG_NF_CONNTRACK_PROCFS
	.print_conntrack	= sctp_print_conntrack,
#endif
	.on_clash		= sctp_on_clash,
#if IS_ENABLED(CONFIG_NF_CT_NETLINK)
	.nlattr_size		= SCTP_NLATTR_SIZE,
	.to_nlattr		= sctp_to_nlattr,
	.from_nlattr		= nlattr_to_sctp,
	.tuple_to_nlattr	= nf_ct_port_tuple_to_nlattr,
	.nlattr_tuple_size	= nf_ct_port_nlattr_tuple_size,
	.nlattr_to_tuple	= nf_ct_port_nlattr_to_tuple,
	.nla_policy		= nf_ct_port_nla_policy,
#endif
#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
	.ctnl_timeout		= {
		.nlattr_to_obj	= sctp_timeout_nlattr_to_obj,
		.obj_to_nlattr	= sctp_timeout_obj_to_nlattr,
		.nlattr_max	= CTA_TIMEOUT_SCTP_MAX,
		.obj_size	= sizeof(unsigned int) * SCTP_CONNTRACK_MAX,
		.nla_policy	= sctp_timeout_nla_policy,
	},
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */
};