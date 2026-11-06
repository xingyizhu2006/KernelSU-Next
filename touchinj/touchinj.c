// SPDX-License-Identifier: GPL-2.0
/*
 * touchinj — 最小 LKM 触屏注入验证
 *
 * 目标设备: OPD2508 / ColorOS 16 / 6.6.118
 * 触屏: /dev/input/event2, name "touchpanel"
 *   ABS_MT_POSITION_X 0..21199
 *   ABS_MT_POSITION_Y 0..29999
 *   ABS_MT_TOUCH_MAJOR 0..255
 *   ABS_MT_PRESSURE 0..0   -> 不要发 pressure
 *
 * 加载后在 workqueue 里注入一次 tap。参数:
 *   insmod touchinj.ko tap_x=10599 tap_y=50
 *
 * 这只是第一步：验证 input_dev 指针和注入序列。UDP/netfilter 在下一步加。
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

static int tap_x = 10599;
static int tap_y = 50;
module_param(tap_x, int, 0644);
MODULE_PARM_DESC(tap_x, "tap X in touchscreen ABS units");
module_param(tap_y, int, 0644);
MODULE_PARM_DESC(tap_y, "tap Y in touchscreen ABS units");

static struct input_dev *touch_dev;
static struct device *touch_class_dev;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kln;

static int match_touchpanel(struct device *dev, const void *data)
{
	return strcmp(dev_name(dev), (const char *)data) == 0;
}

/*
 * input_class 在本机内核里没有导出（insmod 报 Unknown symbol input_class）。
 * kallsyms_lookup_name 本身也没导出，用 kprobe 拿它的地址，再用它找
 * input_class 的地址。CONFIG_KPROBES=y / CONFIG_KALLSYMS_ALL=y 已确认。
 */
static int resolve_kallsyms(void)
{
	struct kprobe kp;
	int ret;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("touchinj: register_kprobe(kallsyms_lookup_name) failed: %d\n", ret);
		return ret;
	}
	kln = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	if (!kln) {
		pr_err("touchinj: kallsyms_lookup_name is NULL\n");
		return -ENOENT;
	}
	return 0;
}

static int find_touchpanel(void)
{
	struct device *dev;
	struct class *ic;
	int ret;

	if (!kln) {
		ret = resolve_kallsyms();
		if (ret)
			return ret;
	}

	ic = (struct class *)kln("input_class");
	if (!ic) {
		pr_err("touchinj: input_class not found in kallsyms\n");
		return -ENOENT;
	}

	dev = class_find_device(ic, NULL, "touchpanel", match_touchpanel);
	if (!dev)
		return -ENODEV;

	touch_class_dev = dev;
	touch_dev = to_input_dev(dev);
	pr_info("touchinj: found %s at %p\n", dev_name(dev), touch_dev);
	return 0;
}

static void touchinj_work(struct work_struct *work)
{
	struct input_dev *dev = touch_dev;
	int x = tap_x;
	int y = tap_y;

	if (!dev)
		return;

	if (x < 0)
		x = 0;
	if (y < 0)
		y = 0;

	/* 按下 */
	input_mt_slot(dev, 0);
	input_mt_report_slot_state(dev, MT_TOOL_FINGER, true);
	input_event(dev, EV_ABS, ABS_MT_POSITION_X, x);
	input_event(dev, EV_ABS, ABS_MT_POSITION_Y, y);
	input_event(dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 31);
	input_event(dev, EV_KEY, BTN_TOOL_FINGER, 1);
	input_event(dev, EV_KEY, BTN_TOUCH, 1);
	input_sync(dev);

	msleep(30);

	/* 抬起 */
	input_mt_slot(dev, 0);
	input_mt_report_slot_state(dev, MT_TOOL_FINGER, false);
	input_event(dev, EV_ABS, ABS_MT_TOUCH_MAJOR, 0);
	input_event(dev, EV_KEY, BTN_TOOL_FINGER, 0);
	input_event(dev, EV_KEY, BTN_TOUCH, 0);
	input_sync(dev);

	pr_info("touchinj: tap %d,%d done\n", x, y);
}

static DECLARE_WORK(tap_work, touchinj_work);

static int __init touchinj_init(void)
{
	int ret;

	ret = find_touchpanel();
	if (ret) {
		pr_err("touchinj: touchpanel not found (%d)\n", ret);
		return ret;
	}

	schedule_work(&tap_work);
	pr_info("touchinj: loaded, tap queued\n");
	return 0;
}

static void __exit touchinj_exit(void)
{
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
MODULE_DESCRIPTION("Minimal touchscreen injection LKM for OPD2508");
