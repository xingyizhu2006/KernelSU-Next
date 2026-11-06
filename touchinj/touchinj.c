// SPDX-License-Identifier: GPL-2.0
/*
 * touchinj — LKM 触屏注入 + UDP netfilter（OPD2508 / 6.6.118）
 *
 * 触屏: /dev/input/event2, name "touchpanel"
 *   ABS_MT_POSITION_X 0..21199
 *   ABS_MT_POSITION_Y 0..29999
 *   ABS_MT_TOUCH_MAJOR 0..255
 *   ABS_MT_PRESSURE 0..0   -> 不发 pressure
 *
 * UDP 包格式（18 字节，little-endian，packed）:
 *   u32 magic=0x31484354 ("TCH1")
 *   u32 seq
 *   u8  type  1=tap 2=down 3=move 4=up
 *   u8  contact
 *   u16 x, u16 y
 *   u16 major
 *   u16 reserved
 *
 * 设计:
 *   - netfilter PRE_ROUTING + NF_IP_PRI_FIRST + NF_STOLEN
 *     -> 没有 socket、没有 /proc/net/udp 条目、没有用户态进程
 *   - hook 只解析/入队，workqueue 里做 input_event
 *   - input_class 没导出，用 kprobe 拿 kallsyms_lookup_name 再找
 */
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

#define TOUCH_MAGIC 0x31484354u
#define TOUCH_QSZ 64

struct __attribute__((packed)) touch_pkt {
	uint32_t magic;
	uint32_t seq;
	uint8_t type;
	uint8_t contact;
	uint16_t x;
	uint16_t y;
	uint16_t major;
	uint16_t reserved;
};

static int tap_x = 10599;
static int tap_y = 50;
static int udp_port = 61069;
static int selftest = 0;
static int debug = 0;
module_param(tap_x, int, 0644);
MODULE_PARM_DESC(tap_x, "selftest tap X in touchscreen ABS units");
module_param(tap_y, int, 0644);
MODULE_PARM_DESC(tap_y, "selftest tap Y in touchscreen ABS units");
module_param(udp_port, int, 0644);
MODULE_PARM_DESC(udp_port, "UDP port to intercept");
module_param(selftest, int, 0644);
MODULE_PARM_DESC(selftest, "inject one tap on load");
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "log netfilter parsing");

static struct input_dev *touch_dev;
static struct device *touch_class_dev;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln;

static struct touch_pkt q[TOUCH_QSZ];
static int qhead, qtail;
static spinlock_t qlock;

static struct work_struct rx_work;
static struct work_struct tap_work;

static int match_touchpanel(struct device *dev, const void *data)
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
		pr_err("touchinj: register_kprobe failed: %d\n", ret);
		return ret;
	}
	kln = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	return kln ? 0 : -ENOENT;
}

static int find_touchpanel(void)
{
	struct class *ic;
	struct device *dev;
	int ret;

	ret = resolve_kallsyms();
	if (ret)
		return ret;

	ic = (struct class *)kln("input_class");
	if (!ic) {
		pr_err("touchinj: input_class not found\n");
		return -ENOENT;
	}

	dev = class_find_device(ic, NULL, "touchpanel", match_touchpanel);
	if (!dev)
		return -ENODEV;

	touch_class_dev = dev;
	touch_dev = to_input_dev(dev);
	pr_info("touchinj: found %s\n", touch_dev->name);
	return 0;
}

static int clamp_axis(int v, int axis)
{
	int lo = input_abs_get_min(touch_dev, axis);
	int hi = input_abs_get_max(touch_dev, axis);

	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

static int clamp_major(int v)
{
	int hi = input_abs_get_max(touch_dev, ABS_MT_TOUCH_MAJOR);

	if (hi <= 0)
		hi = 255;
	if (v < 1)
		return 1;
	if (v > hi)
		return hi;
	return v;
}

static void inj_down(int slot, int x, int y, int major)
{
	input_mt_slot(touch_dev, slot);
	input_mt_report_slot_state(touch_dev, MT_TOOL_FINGER, true);
	input_event(touch_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(touch_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(touch_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);
	input_event(touch_dev, EV_KEY, BTN_TOOL_FINGER, 1);
	input_event(touch_dev, EV_KEY, BTN_TOUCH, 1);
	input_sync(touch_dev);
}

static void inj_move(int slot, int x, int y, int major)
{
	input_mt_slot(touch_dev, slot);
	input_event(touch_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(touch_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(touch_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);
	input_sync(touch_dev);
}

static void inj_up(int slot)
{
	input_mt_slot(touch_dev, slot);
	input_mt_report_slot_state(touch_dev, MT_TOOL_FINGER, false);
	input_event(touch_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 0);
	input_event(touch_dev, EV_KEY, BTN_TOOL_FINGER, 0);
	input_event(touch_dev, EV_KEY, BTN_TOUCH, 0);
	input_sync(touch_dev);
}

static void handle_pkt(const struct touch_pkt *p)
{
	int slot, x, y, major;

	if (!touch_dev)
		return;

	if (debug)
		pr_info_ratelimited("touchinj: handle type=%u x=%u y=%u\n",
				    p->type, p->x, p->y);

	slot = p->contact % 10;
	x = clamp_axis(p->x, ABS_MT_POSITION_X);
	y = clamp_axis(p->y, ABS_MT_POSITION_Y);
	major = clamp_major(p->major ? p->major : 31);

	switch (p->type) {
	case 1:
		inj_down(0, x, y, major);
		msleep(30);
		inj_up(0);
		break;
	case 2:
		inj_down(slot, x, y, major);
		break;
	case 3:
		inj_move(slot, x, y, major);
		break;
	case 4:
		inj_up(slot);
		break;
	}
}

static void rx_work_fn(struct work_struct *work)
{
	struct touch_pkt p;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&qlock, flags);
		if (qhead == qtail) {
			spin_unlock_irqrestore(&qlock, flags);
			break;
		}
		p = q[qhead];
		qhead = (qhead + 1) % TOUCH_QSZ;
		spin_unlock_irqrestore(&qlock, flags);
		handle_pkt(&p);
	}
}

static void tap_work_fn(struct work_struct *work)
{
	struct touch_pkt p = {
		.magic = TOUCH_MAGIC,
		.type = 1,
		.contact = 0,
		.x = tap_x,
		.y = tap_y,
		.major = 31,
	};
	handle_pkt(&p);
}

static unsigned int touch_nf_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *uh;
	struct touch_pkt pkt;
	unsigned int iph_len;
	unsigned long flags;

	if (!skb || !touch_dev)
		return NF_ACCEPT;
	if (debug)
		pr_info_ratelimited("touchinj: hook=%u proto=%04x\n",
				    state->hook, ntohs(skb->protocol));
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
	if (debug)
		pr_info_ratelimited("touchinj: dport=%u len=%u\n",
				    ntohs(uh->dest), ntohs(uh->len));
	if (ntohs(uh->dest) != udp_port)
		return NF_ACCEPT;
	if (ntohs(uh->len) < sizeof(struct udphdr) + sizeof(pkt))
		return NF_ACCEPT;

	memcpy(&pkt, (unsigned char *)uh + sizeof(struct udphdr), sizeof(pkt));
	if (debug)
		pr_info_ratelimited("touchinj: magic=%08x type=%u x=%u y=%u\n",
				    pkt.magic, pkt.type, pkt.x, pkt.y);
	if (pkt.magic != TOUCH_MAGIC || pkt.type < 1 || pkt.type > 4)
		return NF_ACCEPT;

	if (debug)
		pr_info_ratelimited("touchinj: enqueue\n");

	spin_lock_irqsave(&qlock, flags);
	if (((qtail + 1) % TOUCH_QSZ) != qhead) {
		q[qtail] = pkt;
		qtail = (qtail + 1) % TOUCH_QSZ;
	}
	spin_unlock_irqrestore(&qlock, flags);

	schedule_work(&rx_work);
	return NF_STOLEN;
}

static struct nf_hook_ops touch_ops = {
	.hook = touch_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops touch_ops_in = {
	.hook = touch_nf_hook,
	.pf = NFPROTO_IPV4,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST,
};

static int __init touchinj_init(void)
{
	int ret;

	ret = find_touchpanel();
	if (ret) {
		pr_err("touchinj: touchpanel not found (%d)\n", ret);
		return ret;
	}

	spin_lock_init(&qlock);
	INIT_WORK(&rx_work, rx_work_fn);
	INIT_WORK(&tap_work, tap_work_fn);

	ret = nf_register_net_hook(&init_net, &touch_ops);
	if (ret) {
		pr_err("touchinj: nf_register_net_hook(pre) failed: %d\n", ret);
		put_device(touch_class_dev);
		touch_class_dev = NULL;
		touch_dev = NULL;
		return ret;
	}

	ret = nf_register_net_hook(&init_net, &touch_ops_in);
	if (ret) {
		pr_err("touchinj: nf_register_net_hook(local) failed: %d\n", ret);
		nf_unregister_net_hook(&init_net, &touch_ops);
		put_device(touch_class_dev);
		touch_class_dev = NULL;
		touch_dev = NULL;
		return ret;
	}

	if (selftest)
		schedule_work(&tap_work);

	pr_info("touchinj: loaded, udp %d debug %d\n", udp_port, debug);
	return 0;
}

static void __exit touchinj_exit(void)
{
	nf_unregister_net_hook(&init_net, &touch_ops_in);
	nf_unregister_net_hook(&init_net, &touch_ops);
	cancel_work_sync(&rx_work);
	cancel_work_sync(&tap_work);

	if (touch_class_dev) {
		put_device(touch_class_dev);
		touch_class_dev = NULL;
		touch_dev = NULL;
	}

	pr_info("touchinj: unloaded\n");
}

module_init(touchinj_init);
module_exit(touchinj_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("delta-peripheral");
MODULE_DESCRIPTION("Touchscreen injection LKM with UDP netfilter (OPD2508)");
