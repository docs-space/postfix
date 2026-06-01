 /*
  * Test program to exercise db_common.c. See ptest_main.h for a documented
  * example.
  */

 /*
  * System library.
  */
#include <sys_defs.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

 /*
  * Utility library.
  */
#include <dict.h>
#include <msg.h>
#include <mymalloc.h>
#include <vstream.h>
#include <vstring.h>

 /*
  * Global library.
  */
#include <mail_conf.h>
#include "db_common.h"

 /*
  * Test library.
  */
#include <ptest.h>

#define STR(x)	vstring_str(x)

typedef struct PTEST_CASE {
    const char *testname;
    void    (*action) (PTEST_CTX *, const struct PTEST_CASE *);
    const char *template;
    const char *lookup_key;
    const char *want;
} PTEST_CASE;

static DICT test_dict;

static void test_setup_conf(void)
{
    static int setup_done;
    static char conf_dir[] = "/tmp/db_common_test.XXXXXX";
    char   *path;
    VSTREAM *fp;

    if (setup_done)
	return;
    if (mkdtemp(conf_dir) == 0)
	msg_fatal("mkdtemp: %m");
    path = concatenate(conf_dir, "/main.cf", (char *) 0);
    if ((fp = vstream_fopen(path, O_WRONLY | O_CREAT | O_TRUNC, 0600)) == 0)
	msg_fatal("open %s: %m", path);
    if (vstream_fprintf(fp,
			"multi_instance_name = test-node\n"
			"myhostname = mail.example.com\n") < 0
	|| vstream_fclose(fp) != 0)
	msg_fatal("write %s: %m", path);
    if (dict_load_file_xt(CONFIG_DICT, path) == 0)
	msg_fatal("load %s: %m", path);
    myfree(path);
    test_dict.type = "test";
    test_dict.name = "db_common_test";
    setup_done = 1;
}

static void test_expand(PTEST_CTX *t, const PTEST_CASE *tp)
{
    void   *ctx = 0;
    VSTRING *result = vstring_alloc(10);

    test_setup_conf();
    if (db_common_parse(&test_dict, &ctx, tp->template, 1) == 0
	&& strchr(tp->template, '%') != 0
	&& strstr(tp->template, "%{") == 0)
	ptest_error(t, "db_common_parse: expected dynamic template");
    if (!db_common_expand(ctx, tp->template, tp->lookup_key, 0, result, 0))
	ptest_error(t, "db_common_expand failed");
    if (strcmp(STR(result), tp->want) != 0)
	ptest_error(t, "got \"%s\", want \"%s\"", STR(result), tp->want);
    db_common_free_ctx(ctx);
    vstring_free(result);
}

static const PTEST_CASE ptestcases[] = {
    {"cf_param_only", test_expand,
	"SELECT 1 WHERE node = '%{multi_instance_name}'",
	"user@example.com",
	"SELECT 1 WHERE node = 'test-node'"},
    {"cf_param_with_lookup", test_expand,
	"SELECT 1 WHERE email = '%s' AND node = '%{multi_instance_name}'",
	"user@example.com",
	"SELECT 1 WHERE email = 'user@example.com' AND node = 'test-node'"},
    {"cf_param_myhostname", test_expand,
	"SELECT 1 WHERE host = '%{myhostname}'",
	"ignored",
	"SELECT 1 WHERE host = 'mail.example.com'"},
    {"literal_percent", test_expand,
	"SELECT 1 WHERE pct = '%%' AND node = '%{multi_instance_name}'",
	"user@example.com",
	"SELECT 1 WHERE pct = '%' AND node = 'test-node'"},
};

#include <ptest_main.h>
