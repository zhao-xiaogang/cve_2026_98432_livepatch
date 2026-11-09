/*
CVE-2026-98432: IPv4 option lifetime fix.
Target: Ubuntu 22 5.15.0-71-generic
Complete function bodies were reviewed for this target.
Other kernel builds require a separate source/API review.
Upstream fix: https://github.com/torvalds/linux/commit/e3f33b0a1d89d738e2b913dab519226eaf76e15b
*/

#define TARGET_KERNEL "5.15.0-71-generic"

#include <linux/version.h>
#include <linux/livepatch.h>
#include <linux/utsname.h>
#include <net/inet_sock.h>

// net/ipv4/af_inet.c inet_sock_destruct()
// https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy/tree/net/ipv4/af_inet.c?h=Ubuntu-5.15.0-71.78#n131
static void patched_inet_sock_destruct(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);

	__skb_queue_purge(&sk->sk_receive_queue);
	if (sk->sk_rx_skb_cache) {
		__kfree_skb(sk->sk_rx_skb_cache);
		sk->sk_rx_skb_cache = NULL;
	}
	__skb_queue_purge(&sk->sk_error_queue);

	sk_mem_reclaim(sk);

	if (sk->sk_type == SOCK_STREAM && sk->sk_state != TCP_CLOSE) {
		pr_err("Attempt to release TCP socket in state %d %p\n",
		       sk->sk_state, sk);
		return;
	}
	if (!sock_flag(sk, SOCK_DEAD)) {
		pr_err("Attempt to release alive inet socket %p\n", sk);
		return;
	}

	WARN_ON(atomic_read(&sk->sk_rmem_alloc));
	WARN_ON(refcount_read(&sk->sk_wmem_alloc));
	WARN_ON(sk->sk_wmem_queued);
	WARN_ON(sk->sk_forward_alloc);

	kfree_rcu(rcu_dereference_protected(inet->inet_opt, 1), rcu);
	dst_release(rcu_dereference_protected(sk->sk_dst_cache, 1));
	dst_release(rcu_dereference_protected(sk->sk_rx_dst, 1));
	sk_refcnt_debug_dec(sk);
}

// net/ipv4/tcp_ipv4.c tcp_v4_reqsk_destructor()
// https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/jammy/tree/net/ipv4/tcp_ipv4.c?h=Ubuntu-5.15.0-71.78#n1035
static void patched_tcp_v4_reqsk_destructor(struct request_sock *req)
{
	kfree_rcu(rcu_dereference_protected(inet_rsk(req)->ireq_opt, 1), rcu);
}

static struct klp_func funcs[] = {
	{
		.old_name = "inet_sock_destruct",
		.new_func = patched_inet_sock_destruct,
	}, {
		.old_name = "tcp_v4_reqsk_destructor",
		.new_func = patched_tcp_v4_reqsk_destructor,
	}, { }
};

static struct klp_object objects[] = {
	{ .funcs = funcs },
	{ }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objects,
};

static int __init cve_2026_98432_init(void)
{
	int ret;

	if (strcmp(utsname()->release, TARGET_KERNEL)) {
		pr_err("fix_cve_2026_98432: requires kernel %s\n", TARGET_KERNEL);
		return -EINVAL;
	}

	ret = klp_enable_patch(&patch);
	if (ret)
		return ret;
	pr_info("fix_cve_2026_98432: IPv4 option livepatch enabled\n");
	return 0;
}

static void __exit cve_2026_98432_exit(void)
{
	rcu_barrier();
}

module_init(cve_2026_98432_init);
module_exit(cve_2026_98432_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhao-xiaogang");
MODULE_DESCRIPTION("FIX-CVE-2026-98432: defer IPv4 option frees through RCU");
MODULE_INFO(livepatch, "Y");
MODULE_INFO(target_kernel, TARGET_KERNEL);
