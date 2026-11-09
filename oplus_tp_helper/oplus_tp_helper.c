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
 * UDP 包格式（24 字节，little-endian，packed）:
 *   u32 magic=0x31484354
 *   u32 seq
 *   u32 token      0 = 不校验
 *   u8  type       1=tap 2=down 3=move 4=up 5=gyro
 *   u8  contact    0..9
 *   u16 x, u16 y
 *   u16 major     0 = 由模块随机 18..40
 *   u16 reserved
 *   u16 reserved2
 *
 * type=5 (陀螺仪注入):
 *   x, y, major  按 int16 解释 -> 三轴角速度，单位 1/1024 rad/s（1024 ≈ 1 rad/s）
 *   reserved     保持时间 ms，0 = 默认 120ms，超时归零
 *   模块左移 10 位换成 hf_manager raw 后，在 hf_manager_report_event()
 *   入队前加到 type==gyro_type 的事件上
 *
 * 接触状态机在模块内维护：
 *   - BTN_TOUCH / BTN_TOOL_FINGER 只在 0<->1 个接触时翻转，多指不会误抬起
 *   - tap 由 delayed work 在 25..45ms 随机延时后抬起，不阻塞 workqueue
 *   - down 之后 1500ms 没有同槽更新则自动抬起（PC 端崩溃不会卡住触点）
 *   - TOUCH_MAJOR 按下时随机 18..40，move 时只做 ±2 抖动，避免恒定面积特征
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
#include <linux/jiffies.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/if_ether.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/random.h>
#include <net/net_namespace.h>

#define TP_MAGIC 0x31484354u
#define TP_QSZ 256
#define TP_UDP_PORT 61069
#define TP_SLOTS 10
#define TP_STALE_MS 1500
#define TP_TICK_MS 20

static int hide = 0;
module_param(hide, int, 0644);
MODULE_PARM_DESC(hide, "hide module from /proc/modules and /sys/module");

static unsigned int token = 0;
module_param(token, uint, 0644);
MODULE_PARM_DESC(token, "shared token required in packet, 0 = disabled");

/* ---------------- 陀螺仪注入参数 ---------------- */

/*
 * hf_manager_event (0x4c 字节，MTK sensor 2.0 -> hf_manager -> HAL)：
 *   0x00 int64 timestamp
 *   0x08 u8    type      Android 传感器类型（4 = TYPE_GYROSCOPE）
 *   0x09 u8    accuracy
 *   0x0a u8    action    0 = 数据事件
 *   0x0b u8    pad
 *   0x0c s32   data[16]  raw 值，HAL 侧除以 resolution 得到 rad/s
 */
#define HFE_TYPE_OFF	8
#define HFE_ACTION_OFF	10
#define HFE_DATA_OFF	12

static int gyro_type = 4;
module_param(gyro_type, int, 0644);
MODULE_PARM_DESC(gyro_type, "hf_manager_event type of the gyroscope, 0 = disable");

static int gyro_dump;
module_param(gyro_dump, int, 0644);
MODULE_PARM_DESC(gyro_dump, "1 = dump first event per type, 2 = also dump gyro samples");

static char *probe_sym = "hf_manager_report_event";
module_param(probe_sym, charp, 0644);
MODULE_PARM_DESC(probe_sym, "symbol to kprobe for event injection");

static int probe_arg = 1;
module_param(probe_arg, int, 0644);
MODULE_PARM_DESC(probe_arg, "xN register holding the event pointer");

struct __attribute__((packed)) tp_pkt {
	uint32_t magic;
	uint32_t seq;
	uint32_t token;
	uint8_t type;
	uint8_t contact;
	uint16_t x;
	uint16_t y;
	uint16_t major;
	uint16_t reserved;
	uint16_t reserved2;
};

struct tp_slot {
	bool active;
	unsigned long last;
	unsigned long expire;	/* 0 = 无自动抬起 */
	int major;		/* 当前帧上报的触控面积 */
	int major_base;		/* 按下时定的基准，抖动只围绕它 */
};

#define TP_MAJOR_MIN 18
#define TP_MAJOR_SPAN 23	/* 18..40 */
#define TP_TAP_MIN_MS 25
#define TP_TAP_SPAN_MS 21	/* 25..45 */

static struct input_dev *tp_dev;
static struct device *tp_class_dev;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln;

static struct tp_pkt tp_q[TP_QSZ];
static int tp_qhead, tp_qtail;
static spinlock_t tp_qlock;

static struct tp_slot tp_slots[TP_SLOTS];
static int tp_active;
static bool tp_btn;
static DEFINE_MUTEX(tp_mtx);

static struct work_struct tp_rx_work;
static struct delayed_work tp_tick_work;

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
	if (v <= 0)
		return 0;	/* 0 = 交给模块随机 */
	if (v > hi)
		return hi;
	return v;
}

/* 一次接触内面积只做小幅抖动，避免每帧跳变 */
static int jitter_major(int base)
{
	int v = base + (int)get_random_u32_below(5) - 2;

	if (v < TP_MAJOR_MIN)
		v = TP_MAJOR_MIN;
	if (v > TP_MAJOR_MIN + TP_MAJOR_SPAN - 1)
		v = TP_MAJOR_MIN + TP_MAJOR_SPAN - 1;
	return v;
}

static void tp_emit_btn(void)
{
	bool any = tp_active > 0;

	if (any == tp_btn)
		return;
	tp_btn = any;
	input_event(tp_dev, EV_KEY, BTN_TOOL_FINGER, any);
	input_event(tp_dev, EV_KEY, BTN_TOUCH, any);
}

static void tp_slot_down(int slot, int x, int y, int major, unsigned long expire)
{
	struct tp_slot *s = &tp_slots[slot];
	bool was_active = s->active;

	if (major <= 0)
		major = TP_MAJOR_MIN + get_random_u32_below(TP_MAJOR_SPAN);
	s->major = major;
	s->major_base = major;

	input_mt_slot(tp_dev, slot);
	input_mt_report_slot_state(tp_dev, MT_TOOL_FINGER, true);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);

	s->active = true;
	s->last = jiffies;
	s->expire = expire;
	if (!was_active)
		tp_active++;

	tp_emit_btn();
	input_sync(tp_dev);
}

static void tp_slot_move(int slot, int x, int y, int major)
{
	struct tp_slot *s = &tp_slots[slot];

	if (!s->active)
		return;

	if (major <= 0) {
		s->major = jitter_major(s->major_base);
		major = s->major;
	}

	input_mt_slot(tp_dev, slot);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(tp_dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, major);
	s->last = jiffies;
	input_sync(tp_dev);
}

static void tp_slot_up(int slot)
{
	struct tp_slot *s = &tp_slots[slot];

	if (!s->active)
		return;

	input_mt_slot(tp_dev, slot);
	input_mt_report_slot_state(tp_dev, MT_TOOL_FINGER, false);
	input_event(tp_dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 0);

	s->active = false;
	s->expire = 0;
	if (tp_active > 0)
		tp_active--;

	tp_emit_btn();
	input_sync(tp_dev);
}

static void tp_tick_work_fn(struct work_struct *work)
{
	unsigned long now = jiffies;
	bool again = false;
	int i;

	mutex_lock(&tp_mtx);
	for (i = 0; i < TP_SLOTS; i++) {
		struct tp_slot *s = &tp_slots[i];

		if (!s->active)
			continue;
		if (s->expire && time_after_eq(now, s->expire)) {
			tp_slot_up(i);
			continue;
		}
		if (time_after(now, s->last + msecs_to_jiffies(TP_STALE_MS))) {
			tp_slot_up(i);
			continue;
		}
		again = true;
	}
	mutex_unlock(&tp_mtx);

	if (again)
		schedule_delayed_work(&tp_tick_work, msecs_to_jiffies(TP_TICK_MS));
}

static void tp_handle(const struct tp_pkt *p)
{
	int slot, x, y, major;

	if (!tp_dev)
		return;

	slot = p->contact % TP_SLOTS;
	x = clamp_axis(p->x, ABS_MT_POSITION_X);
	y = clamp_axis(p->y, ABS_MT_POSITION_Y);
	major = clamp_major(p->major);

	mutex_lock(&tp_mtx);
	switch (p->type) {
	case 1: {
		unsigned int tap_ms = TP_TAP_MIN_MS +
				      get_random_u32_below(TP_TAP_SPAN_MS);

		tp_slot_down(slot, x, y, major,
			     jiffies + msecs_to_jiffies(tap_ms));
		schedule_delayed_work(&tp_tick_work,
				      msecs_to_jiffies(tap_ms + 5));
		break;
	}
	case 2:
		tp_slot_down(slot, x, y, major, 0);
		schedule_delayed_work(&tp_tick_work,
				      msecs_to_jiffies(TP_TICK_MS));
		break;
	case 3:
		tp_slot_move(slot, x, y, major);
		break;
	case 4:
		tp_slot_up(slot);
		break;
	}
	mutex_unlock(&tp_mtx);
}

/* ---------------- 陀螺仪注入 ---------------- */

static struct kprobe gyro_kp;
static bool gyro_kp_ok;
static DEFINE_SPINLOCK(gyro_lock);
static s32 gyro_off[3];		/* 当前叠加的三轴角速度增量（raw LSB） */
static unsigned long gyro_expire;
static u8 gyro_seen[32];	/* dump: 每个 type 只打印一次 */
static int gyro_sampled;

static void gyro_set(const struct tp_pkt *p)
{
	unsigned long flags;
	unsigned int hold = p->reserved ? p->reserved : 120;

	spin_lock_irqsave(&gyro_lock, flags);
	/* 陀螺仪 raw 分辨率约 2^20 LSB/(rad/s)，包里按 1/1024 rad/s 传 */
	gyro_off[0] = (s32)(s16)p->x * 1024;
	gyro_off[1] = (s32)(s16)p->y * 1024;
	gyro_off[2] = (s32)(s16)p->major * 1024;
	gyro_expire = jiffies + msecs_to_jiffies(hold);
	spin_unlock_irqrestore(&gyro_lock, flags);
}

static int gyro_kp_pre(struct kprobe *p, struct pt_regs *regs)
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

	if (gyro_dump && type < 256 &&
	    !(gyro_seen[type >> 3] & (1u << (type & 7)))) {
		gyro_seen[type >> 3] |= 1u << (type & 7);
		pr_info("ev type=%u action=%u data=%d %d %d %d\n", type, action,
			*(s32 *)(ev + HFE_DATA_OFF),
			*(s32 *)(ev + HFE_DATA_OFF + 4),
			*(s32 *)(ev + HFE_DATA_OFF + 8),
			*(s32 *)(ev + HFE_DATA_OFF + 12));
	}

	if (type != gyro_type || action != 0)
		return 0;

	spin_lock_irqsave(&gyro_lock, flags);
	if (time_after(jiffies, gyro_expire)) {
		gyro_off[0] = 0;
		gyro_off[1] = 0;
		gyro_off[2] = 0;
	}
	o[0] = gyro_off[0];
	o[1] = gyro_off[1];
	o[2] = gyro_off[2];
	spin_unlock_irqrestore(&gyro_lock, flags);

	if (gyro_dump >= 2 && gyro_sampled < 40) {
		gyro_sampled++;
		pr_info("gyro raw=%d %d %d add=%d %d %d\n",
			*(s32 *)(ev + HFE_DATA_OFF),
			*(s32 *)(ev + HFE_DATA_OFF + 4),
			*(s32 *)(ev + HFE_DATA_OFF + 8),
			o[0], o[1], o[2]);
	}

	if (!o[0] && !o[1] && !o[2])
		return 0;

	*(s32 *)(ev + HFE_DATA_OFF) += o[0];
	*(s32 *)(ev + HFE_DATA_OFF + 4) += o[1];
	*(s32 *)(ev + HFE_DATA_OFF + 8) += o[2];
	return 0;
}

static int gyro_probe_init(void)
{
	int ret;

	if (gyro_type <= 0)
		return 0;

	memset(&gyro_kp, 0, sizeof(gyro_kp));
	gyro_kp.symbol_name = probe_sym;
	gyro_kp.pre_handler = gyro_kp_pre;

	ret = register_kprobe(&gyro_kp);
	if (ret) {
		pr_warn("kprobe %s failed: %d (gyro disabled)\n", probe_sym, ret);
		return ret;
	}
	gyro_kp_ok = true;
	pr_info("kprobe %s @ %px, gyro_type=%d arg=x%d\n",
		probe_sym, gyro_kp.addr, gyro_type, probe_arg);
	return 0;
}

static void gyro_probe_exit(void)
{
	if (gyro_kp_ok) {
		unregister_kprobe(&gyro_kp);
		gyro_kp_ok = false;
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

		if (token && p.token != token)
			continue;
		if (p.type == 5)
			gyro_set(&p);
		else
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

	if (!skb || (!tp_dev && !gyro_kp_ok))
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
	if (pkt.magic != TP_MAGIC || pkt.type < 1 || pkt.type > 5)
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

static void tp_hide_module(void)
{
	if (!hide)
		return;

	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del_init(&THIS_MODULE->list);
}

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
	INIT_DELAYED_WORK(&tp_tick_work, tp_tick_work_fn);

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

	gyro_probe_init();
	tp_hide_module();
	return 0;

err_unreg_pre:
	nf_unregister_net_hook(&init_net, &tp_ops);
err_put:
	put_device(tp_class_dev);
	tp_class_dev = NULL;
	tp_dev = NULL;
	return ret;
}

static void __exit oplus_tp_helper_exit(void)
{
	int i;

	gyro_probe_exit();
	nf_unregister_net_hook(&init_net, &tp_ops_in);
	nf_unregister_net_hook(&init_net, &tp_ops);
	cancel_work_sync(&tp_rx_work);
	cancel_delayed_work_sync(&tp_tick_work);

	mutex_lock(&tp_mtx);
	for (i = 0; i < TP_SLOTS; i++)
		tp_slot_up(i);
	mutex_unlock(&tp_mtx);

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
