// SPDX-License-Identifier: GPL-2.0
/*
 * oplus_tp_helper — OPPO touch panel helper module
 *
 * 目标: OPD2508 / ColorOS 16 / 6.6.118
 * 触屏: /dev/input/event2, name "touchpanel"
 *   ABS_MT_POSITION_X 0..21199
 *   ABS_MT_POSITION_Y 0..29999
 *   ABS_MT_TOUCH_MAJOR 0..255
 *   ABS_MT_PRESSURE 0..0   -> 不发 pressure
 *
 * UDP 包格式（18 字节，little-endian，packed）:
 *   u32 magic=0x31484354
 *   u32 seq
 *   u8  type  1=tap 2=down 3=move 4=up
 *   u8  contact
 *   u16 x, u16 y
 *   u16 major
 *   u16 reserved
 */
#define pr_fmt(fmt) "oplus_tp_helper: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/if_ether.h>
#include <net/net_namespace.h>

#define TP_MAGIC 0x31484354u
#define TP_QSZ 64
#define TP_UDP_PORT 61069

struct __attribute__((packed)) tp_pkt {
	uint32_t magic;
	uint32_t seq;
	uint8_t type;
	uint8_t contact;
	uint16_t x;
	uint16_t y;
	uint16_t major;
	uint16_t reserved;
};

static struct input_dev *tp_dev;
static struct device *tp_class_dev;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln;

static struct tp_pkt tp_q[TP_QSZ];
static int tp_qhead, tp_qtail;
static spinlock_t tp_qlock;

static struct work_struct tp_rx_work;

static int match_tp(struct device *dev, const void *data)
{
	struct input_dev *idev = to_input_dev(dev);

	if (!idev || !idev->name)
		return 0;
	return strcmp(idev->name, (const char *)data) == 0;
}

static int resolve_kallsyms(void)
{
	struct kprobe kp;
	int ret;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed: %d\n", ret);
		return ret;
	}
	kln = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return kln ? 0 : -ENOENT;
}

static int find_tp(void)
{
	struct class *ic;
	struct device *dev;
	int ret;

	ret = resolve_kallsyms();
	if (ret)
		return ret;

	ic = (struct class *)kln("input_class");
	if (!ic)
		return -ENOENT;

	dev = class_find_device(ic, NULL, "touchpanel", match_tp);
	if (!dev)
		return -ENODEV;

	tp_class_dev = dev;
	tp_dev = to_input_dev(dev);
	return 0;
}

static int clamp_axis(int v, int axis)
{
	int lo = input_abs_get_min(tp_dev, axis);
	int hi = input_abs_get_max(tp_dev, axis);

	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

static int clamp_major(int v)
{
	int hi = input_abs_get_max(tp_dev, ABS_MT_TOUCH_MAJOR);

	if (hi <= 0)
		hi = 255;
	if (v < 1)
		return 1;
	if (v > hi)
		return hi;
	return v;
}

static void tp_down(int slot, int x, int y, int major)
{
	input_mt_slot(tp_dev, slot);
	input_mt_report_slot_state(tp_dev, MT_TOOL_FINGER, true);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);
	input_event(tp_dev, EV_KEY, BTN_TOOL_FINGER, 1);
	input_event(tp_dev, EV_KEY, BTN_TOUCH, 1);
	input_sync(tp_dev);
}

static void tp_move(int slot, int x, int y, int major)
{
	input_mt_slot(tp_dev, slot);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);
	input_sync(tp_dev);
}

static void tp_up(int slot)
{
	input_mt_slot(tp_dev, slot);
	input_mt_report_slot_state(tp_dev, MT_TOOL_FINGER, false);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 0);
	input_event(tp_dev, EV_KEY, BTN_TOOL_FINGER, 0);
	input_event(tp_dev, EV_KEY, BTN_TOUCH, 0);
	input_sync(tp_dev);
}

static void tp_handle(const struct tp_pkt *p)
{
	int slot, x, y, major;

	if (!tp_dev)
		return;

	slot = p->contact % 10;
	x = clamp_axis(p->x, ABS_MT_POSITION_X);
	y = clamp_axis(p->y, ABS_MT_POSITION_Y);
	major = clamp_major(p->major ? p->major : 31);

	switch (p->type) {
	case 1:
		tp_down(0, x, y, major);
		msleep(30);
		tp_up(0);
		break;
	case 2:
		tp_down(slot, x, y, major);
		break;
	case 3:
		tp_move(slot, x, y, major);
		break;
	case 4:
		tp_up(slot);
		break;
	}
}

static void tp_rx_work_fn(struct work_struct *work)
{
	struct tp_pkt p;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&tp_qlock, flags);
		if (tp_qhead == tp_qtail) {
			spin_unlock_irqrestore(&tp_qlock, flags);
			break;
		}
		p = tp_q[tp_qhead];
		tp_qhead = (tp_qhead + 1) % TP_QSZ;
		spin_unlock_irqrestore(&tp_qlock, flags);
		tp_handle(&p);
	}
}

static unsigned int tp_nf_hook(void *priv, struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *uh;
	struct tp_pkt pkt;
	unsigned int iph_len;
	unsigned long flags;

	(void)state;

	if (!skb || !tp_dev)
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
	if (ntohs(uh->dest) != TP_UDP_PORT)
		return NF_ACCEPT;
	if (ntohs(uh->len) < sizeof(struct udphdr) + sizeof(pkt))
		return NF_ACCEPT;

	memcpy(&pkt, (unsigned char *)uh + sizeof(struct udphdr), sizeof(pkt));
	if (pkt.magic != TP_MAGIC || pkt.type < 1 || pkt.type > 4)
		return NF_ACCEPT;

	spin_lock_irqsave(&tp_qlock, flags);
	if (((tp_qtail + 1) % TP_QSZ) != tp_qhead) {
		tp_q[tp_qtail] = pkt;
		tp_qtail = (tp_qtail + 1) % TP_QSZ;
	}
	spin_unlock_irqrestore(&tp_qlock, flags);

	schedule_work(&tp_rx_work);
	return NF_STOLEN;
}

static struct nf_hook_ops tp_ops = {
	.hook = tp_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops tp_ops_in = {
	.hook = tp_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST,
};

static int __init oplus_tp_helper_init(void)
{
	int ret;

	ret = find_tp();
	if (ret) {
		pr_err("touchpanel not found (%d)\n", ret);
		return ret;
	}

	spin_lock_init(&tp_qlock);
	INIT_WORK(&tp_rx_work, tp_rx_work_fn);

	ret = nf_register_net_hook(&init_net, &tp_ops);
	if (ret) {
		pr_err("nf_register_net_hook(pre) failed: %d\n", ret);
		goto err_put;
	}

	ret = nf_register_net_hook(&init_net, &tp_ops_in);
	if (ret) {
		pr_err("nf_register_net_hook(local) failed: %d\n", ret);
		goto err_unreg_pre;
	}

	return 0;

err_put:
	put_device(tp_class_dev);
	tp_class_dev = NULL;
	tp_dev = NULL;
	return ret;

err_unreg_pre:
	nf_unregister_net_hook(&init_net, &tp_ops);
	put_device(tp_class_dev);
	tp_class_dev = NULL;
	tp_dev = NULL;
	return ret;
}

static void __exit oplus_tp_helper_exit(void)
{
	nf_unregister_net_hook(&init_net, &tp_ops_in);
	nf_unregister_net_hook(&init_net, &tp_ops);
	cancel_work_sync(&tp_rx_work);

	if (tp_class_dev) {
		put_device(tp_class_dev);
		tp_class_dev = NULL;
		tp_dev = NULL;
	}
}

module_init(oplus_tp_helper_init);
module_exit(oplus_tp_helper_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OPPO");
MODULE_DESCRIPTION("OPPO touch panel helper");
