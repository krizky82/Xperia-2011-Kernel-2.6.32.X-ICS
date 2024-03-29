#ifdef CONFIG_SCHED_AUTOGROUP

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>

unsigned int __read_mostly sysctl_sched_autogroup_enabled = 1;

struct autogroup {
	struct task_group	*tg;
	struct kref		kref;
	struct rw_semaphore 	lock;
	unsigned long		id;
	int			nice;
};

static struct autogroup autogroup_default;
static atomic_t autogroup_seq_nr;

static void __init autogroup_init(struct task_struct *init_task)
{
	autogroup_default.tg = &init_task_group;
	init_task_group.autogroup = &autogroup_default;
	kref_init(&autogroup_default.kref);
	init_rwsem(&autogroup_default.lock);
	init_task->signal->autogroup = &autogroup_default;
}

static inline void autogroup_destroy(struct kref *kref)
{
	struct autogroup *ag = container_of(kref, struct autogroup, kref);
	struct task_group *tg = ag->tg;

	kfree(ag);
	sched_destroy_group(tg);
}

static inline void autogroup_kref_put(struct autogroup *ag)
{
	kref_put(&ag->kref, autogroup_destroy);
}

static inline struct autogroup *autogroup_kref_get(struct autogroup *ag)
{
	kref_get(&ag->kref);
	return ag;
}

static inline struct autogroup *autogroup_task_get(struct task_struct *p)
{
	struct autogroup *ag;
	unsigned long flags;

	if (!lock_task_sighand(p, &flags))
		return autogroup_kref_get(&autogroup_default);

	ag = autogroup_kref_get(p->signal->autogroup);
	unlock_task_sighand(p, &flags);

	return ag;
}

static inline struct autogroup *autogroup_create(void)
{
	struct autogroup *ag = kzalloc(sizeof(*ag), GFP_KERNEL);

	if (!ag)
		goto out_fail;

	ag->tg = sched_create_group(&init_task_group);

	if (IS_ERR(ag->tg))
		goto out_fail;

	ag->tg->autogroup = ag;
	kref_init(&ag->kref);
	init_rwsem(&ag->lock);
	ag->id = atomic_inc_return(&autogroup_seq_nr);

	return ag;

out_fail:
	if (ag) {
		kfree(ag);
		WARN_ON(1);
	} else
		WARN_ON(1);

	return autogroup_kref_get(&autogroup_default);
}

static inline bool
task_wants_autogroup(struct task_struct *p, struct task_group *tg)
{
	if (tg != &root_task_group)
		return false;

	if (p->sched_class != &fair_sched_class)
		return false;

	/*
	 * We can only assume the task group can't go away on us if
	 * autogroup_move_group() can see us on ->thread_group list.
	 */
	if (p->flags & PF_EXITING)
		return false;

	return true;
}

static inline struct task_group *
autogroup_task_group(struct task_struct *p, struct task_group *tg)
{
	int enabled = ACCESS_ONCE(sysctl_sched_autogroup_enabled);

	if (enabled && task_wants_autogroup(p, tg))
		return p->signal->autogroup->tg;

	return tg;
}

static void
autogroup_move_group(struct task_struct *p, struct autogroup *ag)
{
	struct autogroup *prev;
	struct task_struct *t;

	spin_lock(&p->sighand->siglock);

	prev = p->signal->autogroup;
	if (prev == ag) {
		spin_unlock(&p->sighand->siglock);
		return;
	}

	p->signal->autogroup = autogroup_kref_get(ag);

	if (!ACCESS_ONCE(sysctl_sched_autogroup_enabled))
		goto out;

	t = p;

	do {
		sched_move_task(p);
	} while_each_thread(p, t);

out:
	spin_unlock(&p->sighand->siglock);
	autogroup_kref_put(prev);
}

/* Allocates GFP_KERNEL, cannot be called under any spinlock */
void sched_autogroup_create_attach(struct task_struct *p)
{
	struct autogroup *ag = autogroup_create();

	autogroup_move_group(p, ag);
	/* drop extra refrence added by autogroup_create() */
	autogroup_kref_put(ag);
}
EXPORT_SYMBOL(sched_autogroup_create_attach);

/* Cannot be called under siglock.  Currently has no users */
void sched_autogroup_detach(struct task_struct *p)
{
	autogroup_move_group(p, &autogroup_default);
}
EXPORT_SYMBOL(sched_autogroup_detach);

void sched_autogroup_fork(struct signal_struct *sig)
{
	sig->autogroup = autogroup_task_get(current);
}

void sched_autogroup_exit(struct signal_struct *sig)
{
	autogroup_kref_put(sig->autogroup);
}

static int __init setup_autogroup(char *str)
{
	sysctl_sched_autogroup_enabled = 0;

	return 1;
}

__setup("noautogroup", setup_autogroup);

#ifdef CONFIG_PROC_FS

static inline struct autogroup *autogroup_get(struct task_struct *p)
{
	struct autogroup *ag;

	/* task may be moved after we unlock.. tough */
	spin_lock(&p->sighand->siglock);
	ag = autogroup_kref_get(p->signal->autogroup);
	spin_unlock(&p->sighand->siglock);

	return ag;
}

int proc_sched_autogroup_set_nice(struct task_struct *p, int nice)
{
	static unsigned long next = INITIAL_JIFFIES;
	struct autogroup *ag;
	int err;

	if (nice < -20 || nice > 19)
		return -EINVAL;

	err = security_task_setnice(current, nice);
	if (err)
		return err;

	if (nice < 0 && !can_nice(current, nice))
		return -EPERM;

	/* this is a heavy operation taking global locks.. */
	if (!capable(CAP_SYS_ADMIN) && time_before(jiffies, next))
		return -EAGAIN;

	next = HZ / 10 + jiffies;;
	ag = autogroup_get(p);

	down_write(&ag->lock);
	err = sched_group_set_shares(ag->tg, prio_to_weight[nice + 20]);
	if (!err)
		ag->nice = nice;
	up_write(&ag->lock);

	autogroup_kref_put(ag);

	return err;
}

void proc_sched_autogroup_show_task(struct task_struct *p, struct seq_file *m)
{
	struct autogroup *ag = autogroup_get(p);

	down_read(&ag->lock);
	seq_printf(m, "/autogroup-%ld nice %d\n", ag->id, ag->nice);
	up_read(&ag->lock);

	autogroup_kref_put(ag);
}
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_SCHED_DEBUG
static inline int autogroup_path(struct task_group *tg, char *buf, int buflen)
{
	return snprintf(buf, buflen, "%s-%ld", "/autogroup", tg->autogroup->id);
}
#endif /* CONFIG_SCHED_DEBUG */

#endif /* CONFIG_SCHED_AUTOGROUP */
