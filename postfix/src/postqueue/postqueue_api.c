/*++
/* NAME
/*	postqueue_api 3
/* SUMMARY
/*	programmatic queue listing for postapi
/*--*/

#include <sys_defs.h>
#include <unistd.h>
#include <errno.h>

#include <mail_conf.h>
#include <mail_params.h>
#include <mail_addr.h>
#include <mail_proto.h>
#include <attr.h>
#include <connect.h>
#include <msg.h>
#include <vstream.h>
#include <user_acl.h>

#include <postqueue.h>

int     var_dup_filter_limit;
char   *var_empty_addr;

extern char *var_showq_acl;

static const CONFIG_INT_TABLE int_table[] = {
    VAR_DUP_FILTER_LIMIT, DEF_DUP_FILTER_LIMIT, &var_dup_filter_limit, 0, 0,
    0,
};

static const CONFIG_STR_TABLE str_table[] = {
    VAR_SHOWQ_ACL, DEF_SHOWQ_ACL, &var_showq_acl, 0, 0,
    VAR_EMPTY_ADDR, DEF_EMPTY_ADDR, &var_empty_addr, 1, 0,
    0,
};

 /* showq_client_json - run the showq protocol client (JSON listing) */

static void
showq_client_json(VSTREAM *showq, VSTREAM *fp)
{
    if (attr_scan(showq, ATTR_FLAG_STRICT,
		  RECV_ATTR_STREQ(MAIL_ATTR_PROTO, MAIL_ATTR_PROTO_SHOWQ),
		  ATTR_TYPE_END) != 0)
	msg_fatal("malformed showq server response");
    showq_json_fp(showq, fp);
}

/* postqueue_list_json - write queue listing in JSON LINES format to fp */

int
postqueue_list_json(VSTREAM *fp)
{
    const char *errstr;
    VSTREAM *showq;
    uid_t   uid = getuid();

    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_list_json: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (-1);
    }
    if ((showq = mail_connect(MAIL_CLASS_PUBLIC, var_showq_service, BLOCKING)) == 0) {
	msg_warn("postqueue_list_json: connect to the %s %s service: %m",
		 var_mail_name, var_showq_service);
	return (-1);
    }
    showq_client_json(showq, fp);
    if (vstream_fclose(showq))
	msg_warn("postqueue_list_json: close showq: %m");
    return (0);
}

/* postqueue_list_json_by_queue - write one queue listing as JSON LINES */

int
postqueue_list_json_by_queue(VSTREAM *fp, const char *queue_name)
{
    const char *errstr;
    uid_t   uid = getuid();

    if (queue_name == 0 || *queue_name == 0)
	return (0);
    mail_conf_read();
    get_mail_conf_int_table(int_table);
    get_mail_conf_str_table(str_table);
    if (uid != 0 && uid != var_owner_uid
	&& (errstr = check_user_acl_byuid(VAR_SHOWQ_ACL, var_showq_acl,
					  uid)) != 0) {
	msg_warn("postqueue_list_json_by_queue: %s(%ld) is not allowed to view the mail queue",
		 errstr, (long) uid);
	return (-1);
    }
    if (postqueue_scan_queue_json(fp, queue_name) < 0) {
	msg_warn("postqueue_list_json_by_queue: queue scan failed for %s",
		 queue_name);
	return (-1);
    }
    return (0);
}
