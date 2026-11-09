// SPDX-License-Identifier: GPL-2.0
/*
 * oplus_gyro_helper — 陀螺仪注入测试模块（可与 oplus_tp_helper 共存）
 *
 * 目标链路:
 *   SCP -> sensorhub.ko -> hf_manager.ko -> /dev/hf_manager -> sensors HAL
 *
 * 注入点: kprobe hf_manager_report_event(manager, event)
 *   event 结构 0x4c 字节:
 *     0x00 int64 timestamp
 *     0x08 u8    type      Android 传感器类型（4 = gyro）
 *     0x09 u8    accuracy
 *     0x0a u8    action    0 = 数据事件
 *     0x0b u8    pad
 *     0x0c s32   data[16]  raw 值，HAL 除以 resolution 得到 rad/s
 *
 * UDP 包 24 字节（little-endian, packed），端口 61070:
 *   u32 magic = 0x31484354
 *   u32 seq
 *   u32 token     0 = 不校验
 *   u8  type      1 = 设置角速度增量, 2 = 清零
 *   u8  pad
 *   s16 x, s16 y, s16 z   增量，单位 = hf_manager raw LSB
 *   u16 hold      保持时间 ms，0 = 默认 120
 *   u16 pad2
 */
#define pr_fmt(fmt) "oplus_gyro_helper: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <net/net_namespace.h>

#define GH_MAGIC 0x31484354u
#define GH_PORT 61070
#define GH_QSZ 64

#define HFE_TYPE_OFF 8
#define HFE_ACTION_OFF 10
#define HFE_DATA_OFF 12

static int gyro_type = 4;
module_param(gyro_type, int, 0644);
MODULE_PARM_DESC(gyro_type, "hf_manager_event type of gyroscope, 0 = disable");

static int dump;
module_param(dump, int, 0644);
MODULE_PARM_DESC(dump, "1 = dump first event per type, 2 = also dump gyro samples");

static char *probe_sym = "hf_manager_report_event";
module_param(probe_sym, charp, 0644);
MODULE_PARM_DESC(probe_sym, "symbol to kprobe");

static int probe_arg = 1;
module_param(probe_arg, int, 0644);
MODULE_PARM_DESC(probe_arg, "xN register holding the event pointer");

static int dump_n = 40;
module_param(dump_n, int, 0644);
MODULE_PARM_DESC(dump_n, "how many samples of dump_type to print");

static int dump_type = -1;
module_param(dump_type, int, 0644);
MODULE_PARM_DESC(dump_type, "hf_manager_event type to sample, -1 = gyro_type");

static unsigned int token;
module_param(token, uint, 0644);
MODULE_PARM_DESC(token, "shared token required in packet, 0 = disabled");

struct __attribute__((packed)) gh_pkt {
	uint32_t magic;
	uint32_t seq;
	uint32_t token;
	uint8_t type;
	uint8_t pad;
	int16_t x;
	int16_t y;
	int16_t z;
	uint16_t hold;
	uint16_t pad2;
};

static struct kprobe gh_kp;
static bool gh_kp_ok;
static DEFINE_SPINLOCK(gh_lock);
static s32 gh_off[3];
static unsigned long gh_expire;
static u8 gh_seen[32];
static int gh_sampled;

static struct gh_pkt gh_q[GH_QSZ];
static int gh_qhead, gh_qtail;
static DEFINE_SPINLOCK(gh_qlock);
static struct work_struct gh_work;

static int gh_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	u8 *ev;
	u8 type, action;
	s32 o[3];
	unsigned long flags;

	(void)p;

	if (probe_arg < 0 || probe_arg > 7)
		return 0;
	ev = (u8 *)regs->regs[probe_arg];
	if (!ev || (unsigned long)ev < 0xffff000000000000UL)
		return 0;

	type = *(u8 *)(ev + HFE_TYPE_OFF);
	action = *(u8 *)(ev + HFE_ACTION_OFF);

	if (dump && type < 256 && !(gh_seen[type >> 3] & (1u << (type & 7)))) {
		gh_seen[type >> 3] |= 1u << (type & 7);
		pr_info("ev type=%u action=%u data=%d %d %d %d\n", type, action,
			*(s32 *)(ev + HFE_DATA_OFF),
			*(s32 *)(ev + HFE_DATA_OFF + 4),
			*(s32 *)(ev + HFE_DATA_OFF + 8),
			*(s32 *)(ev + HFE_DATA_OFF + 12));
	}

	if (dump >= 2 && gh_sampled < dump_n &&
	    type == (dump_type < 0 ? gyro_type : dump_type)) {
		gh_sampled++;
		pr_info("ts=%lld type=%u raw=%d %d %d\n",
			(long long)*(s64 *)ev, type,
			*(s32 *)(ev + HFE_DATA_OFF),
			*(s32 *)(ev + HFE_DATA_OFF + 4),
			*(s32 *)(ev + HFE_DATA_OFF + 8));
	}

	if (type != gyro_type || action != 0)
		return 0;

	spin_lock_irqsave(&gh_lock, flags);
	if (time_after(jiffies, gh_expire)) {
		gh_off[0] = 0;
		gh_off[1] = 0;
		gh_off[2] = 0;
	}
	o[0] = gh_off[0];
	o[1] = gh_off[1];
	o[2] = gh_off[2];
	spin_unlock_irqrestore(&gh_lock, flags);

	if (!o[0] && !o[1] && !o[2])
		return 0;

	*(s32 *)(ev + HFE_DATA_OFF) += o[0];
	*(s32 *)(ev + HFE_DATA_OFF + 4) += o[1];
	*(s32 *)(ev + HFE_DATA_OFF + 8) += o[2];
	return 0;
}

static void gh_handle(const struct gh_pkt *p)
{
	unsigned long flags;

	spin_lock_irqsave(&gh_lock, flags);
	if (p->type == 2) {
		gh_off[0] = 0;
		gh_off[1] = 0;
		gh_off[2] = 0;
		gh_expire = jiffies;
	} else {
		unsigned int hold = p->hold ? p->hold : 120;

		/* 陀螺仪 raw 分辨率约 2^20 LSB/(rad/s)，包里按 1/1024 rad/s 传 */
		gh_off[0] = (s32)p->x * 1024;
		gh_off[1] = (s32)p->y * 1024;
		gh_off[2] = (s32)p->z * 1024;
		gh_expire = jiffies + msecs_to_jiffies(hold);
	}
	spin_unlock_irqrestore(&gh_lock, flags);
}

static void gh_work_fn(struct work_struct *work)
{
	struct gh_pkt p;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&gh_qlock, flags);
		if (gh_qhead == gh_qtail) {
			spin_unlock_irqrestore(&gh_qlock, flags);
			break;
		}
		p = gh_q[gh_qhead];
		gh_qhead = (gh_qhead + 1) % GH_QSZ;
		spin_unlock_irqrestore(&gh_qlock, flags);

		if (token && p.token != token)
			continue;
		gh_handle(&p);
	}
}

static unsigned int gh_nf_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *uh;
	struct gh_pkt pkt;
	unsigned int iph_len;
	unsigned long flags;

	(void)priv;
	(void)state;

	if (!skb || !gh_kp_ok)
		return NF_ACCEPT;
	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;
	iph_len = iph->ihl * 4;
	if (iph_len < sizeof(struct iphdr))
		return NF_ACCEPT;
	if (!pskb_may_pull(skb, iph_len + sizeof(struct udphdr) + sizeof(pkt)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	uh = (struct udphdr *)((unsigned char *)iph + iph_len);
	if (ntohs(uh->dest) != GH_PORT)
		return NF_ACCEPT;
	if (ntohs(uh->len) < sizeof(struct udphdr) + sizeof(pkt))
		return NF_ACCEPT;

	memcpy(&pkt, (unsigned char *)uh + sizeof(struct udphdr), sizeof(pkt));
	if (pkt.magic != GH_MAGIC || pkt.type < 1 || pkt.type > 2)
		return NF_ACCEPT;

	spin_lock_irqsave(&gh_qlock, flags);
	if (((gh_qtail + 1) % GH_QSZ) != gh_qhead) {
		gh_q[gh_qtail] = pkt;
		gh_qtail = (gh_qtail + 1) % GH_QSZ;
	}
	spin_unlock_irqrestore(&gh_qlock, flags);

	schedule_work(&gh_work);
	return NF_STOLEN;
}

static struct nf_hook_ops gh_ops_pre = {
	.hook = gh_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops gh_ops_in = {
	.hook = gh_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST,
};

static int __init oplus_gyro_helper_init(void)
{
	int ret;

	spin_lock_init(&gh_qlock);
	spin_lock_init(&gh_lock);
	INIT_WORK(&gh_work, gh_work_fn);

	if (gyro_type > 0) {
		memset(&gh_kp, 0, sizeof(gh_kp));
		gh_kp.symbol_name = probe_sym;
		gh_kp.pre_handler = gh_kp_pre;
		ret = register_kprobe(&gh_kp);
		if (ret) {
			pr_err("kprobe %s failed: %d\n", probe_sym, ret);
			return ret;
		}
		gh_kp_ok = true;
		pr_info("kprobe %s @ %px gyro_type=%d arg=x%d\n",
			probe_sym, gh_kp.addr, gyro_type, probe_arg);
	}

	ret = nf_register_net_hook(&init_net, &gh_ops_pre);
	if (ret) {
		pr_err("nf_register_net_hook(pre): %d\n", ret);
		goto err_kp;
	}
	ret = nf_register_net_hook(&init_net, &gh_ops_in);
	if (ret) {
		pr_err("nf_register_net_hook(local): %d\n", ret);
		goto err_pre;
	}
	return 0;

err_pre:
	nf_unregister_net_hook(&init_net, &gh_ops_pre);
err_kp:
	if (gh_kp_ok) {
		unregister_kprobe(&gh_kp);
		gh_kp_ok = false;
	}
	return ret;
}

static void __exit oplus_gyro_helper_exit(void)
{
	nf_unregister_net_hook(&init_net, &gh_ops_in);
	nf_unregister_net_hook(&init_net, &gh_ops_pre);
	if (gh_kp_ok) {
		unregister_kprobe(&gh_kp);
		gh_kp_ok = false;
	}
	cancel_work_sync(&gh_work);
}

module_init(oplus_gyro_helper_init);
module_exit(oplus_gyro_helper_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OPPO gyroscope injection helper (test)");
