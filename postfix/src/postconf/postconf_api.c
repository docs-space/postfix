/*++
/* NAME
/*	postconf_api 3
/* SUMMARY
/*	programmatic main.cf listing and updates for postapi
/*--*/

#include <sys_defs.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <errno.h>

#include <mail_conf.h>
#include <mail_params.h>
#include <msg.h>
#include <msg_vstream.h>
#include <mymalloc.h>
#include <argv.h>
#include <vstream.h>
#include <vstring.h>
#include <vstring_vstream.h>
#include <split_at.h>
#include <stringops.h>

#include <postconf.h>

extern MSG_LONGJMP_ACTION msg_longjmp_action;

PCF_PARAM_TABLE *pcf_param_table;
PCF_MASTER_ENT *pcf_master_table;
int     pcf_cmd_mode = PCF_DEF_MODE;

static int postconf_api_initialized;
static int postconf_reload_pending;
static ARGV *postconf_apply_pairs;
static int postconf_skip_restore_after_validate;
static jmp_buf postconf_validate_jmp;

static NORETURN postconf_validate_longjmp(int code)
{
    longjmp(postconf_validate_jmp, code);
}

static void postconf_api_free_param_node(void *ptr)
{
    myfree(ptr);
}

/* postconf_api_free_master_table - release master.cf table (array storage) */

static void postconf_api_free_master_table(void)
{
    PCF_MASTER_ENT *masterp;

    if (pcf_master_table == 0)
	return;
    for (masterp = pcf_master_table; masterp->argv != 0; masterp++) {
	myfree(masterp->name_space);
	argv_free(masterp->argv);
	if (masterp->valid_names)
	    htable_free(masterp->valid_names, myfree);
	if (masterp->ro_params)
	    dict_close(masterp->ro_params);
	if (masterp->all_params)
	    dict_close(masterp->all_params);
    }
    myfree((void *) pcf_master_table);
    pcf_master_table = 0;
}

/* postconf_api_reset - tear down postconf in-memory state */

void
postconf_api_reset(void)
{
    if (pcf_param_table != 0) {
	htable_free(pcf_param_table, postconf_api_free_param_node);
	pcf_param_table = 0;
    }
    postconf_api_free_master_table();
    pcf_cleanup_user_parameters();
    postconf_api_initialized = 0;
}

static void postconf_validate_setup(ARGV *pairs)
{
    postconf_api_reset();
    if (!postconf_skip_restore_after_validate)
	mail_conf_flush();
    pcf_read_parameters();
    if (pairs != 0 && pairs->argc > 0)
	pcf_set_parameters(pairs->argv);
    pcf_register_builtin_parameters("postapi", getpid());
    pcf_register_postapi_parameters();
    pcf_read_master(PCF_WARN_ON_OPEN_ERROR);
    pcf_register_service_parameters();
    pcf_register_user_parameters(0);
}

static void postconf_restore_runtime_config(void)
{
    postconf_api_reset();
    mail_conf_flush();
    mail_conf_read();
}

/* postconf_validate_restore_msg_sink - stop writing msg(3) to freed memstream */

static void postconf_validate_restore_msg_sink(void)
{
    msg_vstream_init(var_procname, VSTREAM_ERR);
}

/* postconf_api_set_skip_restore_after_validate - defer restore until HTTP response */

void
postconf_api_set_skip_restore_after_validate(int on)
{
    postconf_skip_restore_after_validate = on;
}

/* postconf_api_finish_validate_restore - run deferred restore after controller */

void
postconf_api_finish_validate_restore(void)
{
    if (postconf_skip_restore_after_validate) {
	postconf_skip_restore_after_validate = 0;
	postconf_restore_runtime_config();
    }
}

static void postconf_validate_pairs(ARGV *pairs)
{
    char  **cpp;
    char   *junk;
    char   *name;
    char   *value;
    const char *err;

    for (cpp = pairs->argv; *cpp != 0; cpp++) {
	junk = mystrdup(*cpp);
	if ((err = split_nameval(junk, &name, &value)) != 0)
	    msg_fatal("%s: \"%s\"", err, junk);
	pcf_validate_parameter_value(name);
	myfree(junk);
    }
}

/* postconf_validate_overrides - check proposed main.cf updates */

int
postconf_validate_overrides(ARGV *pairs, VSTRING *err)
{
    VSTRING *msg_buf;
    VSTREAM *msg_stream;
    MSG_LONGJMP_ACTION saved_action;
    int     except;

    if (pairs == 0 || pairs->argc <= 0) {
	vstring_strcpy(err, "no parameters to update");
	return (-1);
    }
    msg_buf = vstring_alloc(256);
    msg_stream = vstream_memopen(msg_buf, O_WRONLY);
    if (msg_stream == 0) {
	vstring_free(msg_buf);
	vstring_strcpy(err, "out of memory");
	return (-1);
    }
    msg_vstream_init("postapi", msg_stream);
    saved_action = msg_longjmp_action;
    msg_set_longjmp_action(postconf_validate_longjmp);
    except = setjmp(postconf_validate_jmp);
    if (except == 0) {
	postconf_validate_setup(pairs);
	postconf_validate_pairs(pairs);
	msg_set_longjmp_action(saved_action);
	(void) vstream_fclose(msg_stream);
	vstring_free(msg_buf);
	postconf_validate_restore_msg_sink();
	if (!postconf_skip_restore_after_validate)
	    postconf_restore_runtime_config();
	return (0);
    }
    msg_set_longjmp_action(saved_action);
	(void) vstream_fclose(msg_stream);
    trimblanks(vstring_str(msg_buf), 0)[0] = 0;
    if (VSTRING_LEN(msg_buf) > 0)
	vstring_strcpy(err, vstring_str(msg_buf));
    else
	vstring_strcpy(err, "configuration check failed");
    vstring_free(msg_buf);
    postconf_validate_restore_msg_sink();
    postconf_restore_runtime_config();
    return (-1);
}

/* postconf_request_reload - schedule postfix reload after HTTP response */

void
postconf_request_reload(void)
{
    postconf_reload_pending = 1;
}

/* postconf_take_reload_pending - test and clear reload schedule */

int
postconf_take_reload_pending(void)
{
    int     pending = postconf_reload_pending;

    postconf_reload_pending = 0;
    return (pending);
}

/* postconf_request_apply - defer main.cf write until after HTTP response */

void
postconf_request_apply(ARGV *pairs)
{
    postconf_apply_pairs = pairs;
}

/* postconf_take_apply_pairs - take deferred apply list */

ARGV *
postconf_take_apply_pairs(void)
{
    ARGV   *pairs = postconf_apply_pairs;

    postconf_apply_pairs = 0;
    return (pairs);
}

/* postconf_apply_overrides - write updates to main.cf */

int
postconf_apply_overrides(ARGV *pairs)
{
    if (pairs == 0 || pairs->argc <= 0)
	return (-1);
    pcf_edit_main(PCF_EDIT_CONF, (int) pairs->argc, pairs->argv);
    return (0);
}

/* postfix_reload_config - reload Postfix after main.cf change */

int
postfix_reload_config(VSTRING *err)
{
    ARGV   *argv;
    VSTREAM *pipe;
    VSTREAM *fp;
    VSTRING *pid_buf;
    char   *postsuper_path;
    char   *master_pid_path;
    char   *cp;
    long    master_pid;
    int     status;
    int     ch;

    postsuper_path = concatenate(var_command_dir, "/postsuper", (char *) 0);
    argv = argv_alloc(2);
    argv_add(argv, postsuper_path, "active", (char *) 0);
    pipe = vstream_popen(O_RDONLY,
			 CA_VSTREAM_POPEN_ARGV(argv->argv),
			 CA_VSTREAM_POPEN_END);
    argv_free(argv);
    myfree(postsuper_path);
    if (pipe == 0) {
	vstring_strcpy(err, "postsuper active failed to start");
	return (-1);
    }
    status = vstream_pclose(pipe);
    if (status != 0) {
	vstring_strcpy(err, "postsuper active failed");
	return (-1);
    }

    master_pid_path = concatenate(var_queue_dir, "/pid/master.pid", (char *) 0);
    pid_buf = vstring_alloc(32);
    fp = vstream_fopen(master_pid_path, O_RDONLY, 0);
    myfree(master_pid_path);
    if (fp == 0) {
	vstring_free(pid_buf);
	vstring_sprintf(err, "open master.pid: %m");
	return (-1);
    }
    vstring_truncate(pid_buf, 0);
    while ((ch = VSTREAM_GETC(fp)) != VSTREAM_EOF) {
	if (ch == '\n' || ch == '\r')
	    break;
	VSTRING_ADDCH(pid_buf, ch);
    }
    VSTRING_TERMINATE(pid_buf);
    if (vstream_fclose(fp) != 0) {
	vstring_free(pid_buf);
	vstring_strcpy(err, "read master.pid failed");
	return (-1);
    }
    cp = vstring_str(pid_buf);
    while (*cp == ' ' || *cp == '\t')
	cp++;
    master_pid = atol(cp);
    vstring_free(pid_buf);
    if (master_pid <= 0) {
	vstring_strcpy(err, "invalid master.pid");
	return (-1);
    }
    if (kill((pid_t) master_pid, SIGHUP) < 0) {
	vstring_sprintf(err, "kill master pid %ld: %m", master_pid);
	return (-1);
    }
    return (0);
}

/* postconf_list_json - equivalent to postconf -j with no arguments */

void
postconf_list_json(VSTREAM *fp)
{
    static char *names[] = {0};

    if (!postconf_api_initialized) {
	mail_conf_read();
	pcf_read_parameters();
	pcf_register_builtin_parameters("postapi", getpid());
	pcf_register_postapi_parameters();
	pcf_read_master(PCF_WARN_ON_OPEN_ERROR);
	pcf_register_service_parameters();
	pcf_register_user_parameters(0);
	postconf_api_initialized = 1;
    }
    pcf_show_parameters(fp, PCF_SHOW_JSON, PCF_PARAM_MASK_CLASS, names);
}
