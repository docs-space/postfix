/*++
/* NAME
/*	postconf_api 3
/* SUMMARY
/*	programmatic main.cf listing for postapi
/*--*/

#include <sys_defs.h>
#include <unistd.h>

#include <mail_conf.h>
#include <mail_dict.h>
#include <vstream.h>

#include <postconf.h>

PCF_PARAM_TABLE *pcf_param_table;
PCF_MASTER_ENT *pcf_master_table;
int     pcf_cmd_mode = PCF_DEF_MODE;

static int postconf_api_initialized;

/* postconf_list_json - equivalent to postconf -j with no arguments */

void
postconf_list_json(VSTREAM *fp)
{
    static char *names[] = {0};

    if (!postconf_api_initialized) {
	mail_conf_read();
	mail_dict_init();
	pcf_read_parameters();
	pcf_register_builtin_parameters("postapi", getpid());
	pcf_read_master(PCF_WARN_ON_OPEN_ERROR);
	pcf_register_service_parameters();
	pcf_register_user_parameters(0);
	postconf_api_initialized = 1;
    }
    pcf_show_parameters(fp, PCF_SHOW_JSON, PCF_PARAM_MASK_CLASS, names);
}
