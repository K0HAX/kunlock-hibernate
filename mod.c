// SPDX-License-Identifier: GPL-2.0-only
/*
 * mod.c
 *
 * This kernel module allows a machine with SecureBoot active to
 * hibernate, overriding kernel lockdown.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/livepatch.h>
#include <linux/kprobes.h>
#include <linux/secretmem.h>
#include <linux/security.h>
#include <linux/pm.h>
// From security.c
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/dcache.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel_read_file.h>
#include <linux/lsm_hooks.h>
#include <linux/integrity.h>
#include <linux/ima.h>
#include <linux/evm.h>
#include <linux/fsnotify.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/personality.h>
#include <linux/backing-dev.h>
#include <linux/string.h>
#include <linux/msg.h>
#include <net/flow.h>

#define BACKTRACE_DEPTH 16
#define MAX_SYMBOL_LEN 4096

struct security_hook_heads * mod_security_hook_heads;

#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &mod_security_hook_heads->FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})

static unsigned long (*kla)(const char* name);
int* nohibernate;

/* We need to look up nohibernate, get a pointer to kallsyms_lookup_name. */
static int resolve_kla(void)
{
    struct kprobe kla_kp = {.symbol_name = "kallsyms_lookup_name"};

    int ret = register_kprobe(&kla_kp);
    if (ret < 0)
    {
        pr_err("kunlock-suspend: register_kprobe failed (%pe)\n", ERR_PTR(ret));
        return ret;
    }
    pr_devel("kunlock-suspend: resolved kallsyms_lookup_name\n");
    kla = (void*)kla_kp.addr;
    unregister_kprobe(&kla_kp);
    return 0;
}

bool livepatch_hibernation_available(void) {
    pr_info("Patched hibernation_available called\n");
    return false;
    /*
    return *nohibernate == 0 &&
        !cxl_mem_active();
    */
}

int livepatch_security_locked_down(enum lockdown_reason what)
{
    pr_info("Patched security_locked_down called\n");
    // 5 == LOCKDOWN_HIBERNATION
    if (what == 5) {
        return 0;
    }
    return call_int_hook(locked_down, 0, what);
}

static struct klp_func funcs[] = {
    {
        .old_name = "hibernation_available",
        .new_func = livepatch_hibernation_available,
    },
    {
        .old_name = "security_locked_down",
        .new_func = livepatch_security_locked_down,
    }, { }
};

static struct klp_object objs[] = {
    {
        /* name being NULL means vmlinux */
        .funcs = funcs,
    }, { }
};

static struct klp_patch patch = {
    .mod = THIS_MODULE,
    .objs = objs,
};

static int get_nohibernate(void)
{
    int err = resolve_kla();
    if (err < 0)
        return err;
    nohibernate = (int*)kla("nohibernate");
    if (!nohibernate)
    {
        printk(KERN_ERR "kunlock-suspend: failed to find nohibernate symbol\n");
        return -ENOENT;
    }
    return 0;
}

static int get_security_hook_heads(void)
{
    int err = resolve_kla();
    if (err < 0)
        return err;
    mod_security_hook_heads = (struct security_hook_heads*)kla("security_hook_heads");
    if (!mod_security_hook_heads)
    {
        printk(KERN_ERR "kunlock-suspend: failed to find nohibernate symbol\n");
        return -ENOENT;
    }
    return 0;
}

static int livepatch_init(void)
{
    int ret;
    int err;
    err = get_nohibernate();
    if (err < 0)
        return err;
    err = get_security_hook_heads();
    if (err < 0)
        return err;
    ret = klp_enable_patch(&patch);
    if(ret < 0) {
        printk(KERN_ERR "LIVEPATCH MOD: registering the livepatch failed: %d\n", ret);
        return ret;
    }
    pr_info("Patched hibernation_available\n");
    return ret;
}

static void livepatch_exit(void)
{
    pr_info("livepatch hibernation_available unregistered\n");
}

module_init(livepatch_init)
module_exit(livepatch_exit)
MODULE_DESCRIPTION("Module to allow hibernating when kernel lockdown is active");
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

