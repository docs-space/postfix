#include <sys_defs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include <msg.h>

#include <mail_conf.h>
#include <mail_proto.h>
#include <mail_params.h>
#include <mail_open_ok.h>
#include <mail_queue.h>
#include <user_acl.h>

#include <postqueue.h>

extern char *var_showq_acl;

static const CONFIG_STR_TABLE postqueue_hold_str_table[] = {
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    0,
};

static int postqueue_modify_acl_ok(void)
{
    const char *errstr;
    uid_t   uid = getuid();

    mail_conf_read();
    get_mail_conf_str_table(postqueue_hold_str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue: %s(%ld) is not allowed to modify the mail queue",
		 errstr, (long) uid);
	return (0);
    }
    return (1);
}

static int postqueue_hold_exec(const char *queue_id)
{
    static const char *src_queues[] = {
	MAIL_QUEUE_INCOMING,
	MAIL_QUEUE_ACTIVE,
	MAIL_QUEUE_DEFERRED,
	0,
    };
    struct stat st;
    const char **qpp;
    const char *msg_path;
    int     tries;

    for (tries = 0; tries < 2; tries++) {
	for (qpp = src_queues; *qpp != 0; qpp++) {
	    if (mail_open_ok(*qpp, queue_id, &st, &msg_path) != MAIL_OPEN_YES)
		continue;
	    if (mail_queue_rename(queue_id, *qpp, MAIL_QUEUE_HOLD) == 0)
		return (POSTQUEUE_HOLD_OK);
	    return (POSTQUEUE_HOLD_ERROR);
	}
    }
    return (POSTQUEUE_HOLD_NOT_FOUND);
}

static int postqueue_release_exec(const char *queue_id)
{
    struct stat st;
    const char *msg_path;

    if (mail_open_ok(MAIL_QUEUE_HOLD, queue_id, &st, &msg_path) != MAIL_OPEN_YES)
	return (POSTQUEUE_RELEASE_NOT_FOUND);
    if (mail_queue_rename(queue_id, MAIL_QUEUE_HOLD, MAIL_QUEUE_DEFERRED) == 0)
	return (POSTQUEUE_RELEASE_OK);
    return (POSTQUEUE_RELEASE_ERROR);
}

int
postqueue_hold_by_id(const char *queue_id)
{
    if (queue_id == 0 || *queue_id == 0 || !mail_queue_id_ok(queue_id))
	return (POSTQUEUE_HOLD_INVALID);
    if (!postqueue_modify_acl_ok())
	return (POSTQUEUE_HOLD_ERROR);
    return (postqueue_hold_exec(queue_id));
}

int
postqueue_release_by_id(const char *queue_id)
{
    if (queue_id == 0 || *queue_id == 0 || !mail_queue_id_ok(queue_id))
	return (POSTQUEUE_RELEASE_INVALID);
    if (!postqueue_modify_acl_ok())
	return (POSTQUEUE_RELEASE_ERROR);
    return (postqueue_release_exec(queue_id));
}
