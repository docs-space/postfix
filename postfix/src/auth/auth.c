#include <sys_defs.h>
#include <string.h>
#include <stdlib.h>

#include <msg.h>
#include <mymalloc.h>
#include <vstring.h>
#include <vstring_vstream.h>
#include <vstream.h>
#include <split_at.h>
#include <base64_code.h>
#include <mail_version.h>
#include <mail_server.h>
#include <mail_params.h>
#include <mail_dict.h>
#include <signal.h>

#include "auth.h"

static const char auth_ldap_chain_maps_param[] = "auth_ldap_chain_maps";
static const char auth_authenticate_maps_param[] = "auth_authenticate_maps";
static const char auth_cred_cache_ttl_param[] = "auth_cred_cache_ttl";

char   *var_auth_ldap_chain_maps;
char   *var_auth_authenticate_maps;
int     var_auth_cred_cache_ttl;

static const CONFIG_STR_TABLE str_table[] = {
    auth_ldap_chain_maps_param, "", &var_auth_ldap_chain_maps, 0, 0,
    auth_authenticate_maps_param, "", &var_auth_authenticate_maps, 0, 0,
    0,
};

static const CONFIG_INT_TABLE int_table[] = {
    auth_cred_cache_ttl_param, "300", &var_auth_cred_cache_ttl, 0, 86400,
    0,
};

typedef struct AUTH_SESSION {
    struct AUTH_SESSION *next;
    unsigned int request_id;
    char   *mechanism;
    char   *service;
    char   *node;
    char   *lip;
    char   *rip;
    char   *username;
    char   *password;
} AUTH_SESSION;

static void auth_session_free(AUTH_SESSION *sess)
{
    if (sess == 0)
	return;
    if (sess->mechanism)
	myfree(sess->mechanism);
    if (sess->service)
	myfree(sess->service);
    if (sess->node)
	myfree(sess->node);
    if (sess->lip)
	myfree(sess->lip);
    if (sess->rip)
	myfree(sess->rip);
    if (sess->username)
	myfree(sess->username);
    if (sess->password)
	myfree(sess->password);
    myfree(sess);
}

static AUTH_SESSION *auth_session_get(AUTH_SESSION **list, unsigned int id)
{
    AUTH_SESSION *sess;

    for (sess = *list; sess != 0; sess = sess->next) {
	if (sess->request_id == id)
	    return (sess);
    }
    return (0);
}

static void auth_session_unlink(AUTH_SESSION **list, AUTH_SESSION *target)
{
    AUTH_SESSION **pp;

    for (pp = list; *pp != 0; pp = &(*pp)->next) {
	if (*pp == target) {
	    *pp = target->next;
	    return;
	}
    }
}

static void auth_reply_ok(VSTREAM *stream, unsigned int id, const char *user)
{
    vstream_fprintf(stream, "OK\t%u\tuser=%s\n", id, user);
    (void) vstream_fflush(stream);
}

static void auth_reply_fail(VSTREAM *stream, unsigned int id, const char *reason)
{
    vstream_fprintf(stream, "FAIL\t%u\treason=%s\n", id, reason);
    (void) vstream_fflush(stream);
}

static void auth_reply_cont(VSTREAM *stream, unsigned int id, const char *challenge)
{
    vstream_fprintf(stream, "CONT\t%u\t%s\n", id, challenge);
    (void) vstream_fflush(stream);
}

static int auth_parse_plain_credentials(const char *b64, char **user, char **pass)
{
    VSTRING *raw = vstring_alloc(64);
    const unsigned char *p;
    const unsigned char *authc;
    const unsigned char *passwd;
    size_t  len;
    size_t  i;

    *user = 0;
    *pass = 0;
    if (b64 == 0 || *b64 == 0)
	return (0);
    if (base64_decode(raw, b64, (ssize_t) strlen(b64)) <= 0) {
	vstring_free(raw);
	return (0);
    }
    p = (const unsigned char *) vstring_str(raw);
    len = VSTRING_LEN(raw);
    for (i = 0; i < len && p[i] != 0; i++)
	 /* void */ ;
    if (i >= len) {
	vstring_free(raw);
	return (0);
    }
    authc = p + i + 1;
    for (i = (size_t) (authc - p); i < len && p[i] != 0; i++)
	 /* void */ ;
    if (i >= len) {
	vstring_free(raw);
	return (0);
    }
    passwd = p + i + 1;
    if (*authc == 0 || *passwd == 0) {
	vstring_free(raw);
	return (0);
    }
    *user = mystrdup((const char *) authc);
    *pass = mystrdup((const char *) passwd);
    vstring_free(raw);
    return (1);
}

static int auth_perform(const char *login, const char *plain,
		         const char *node, const char *rip, char **auth_user)
{
    AUTH_PG_RESULT pg_result;
    int     cached_success;
    int     ok = 0;

    *auth_user = 0;

    if (auth_cred_cache_lookup(login, node, &cached_success)) {
	if (!cached_success)
	    return (0);
	*auth_user = mystrdup(login);
	return (1);
    }

    memset((void *) &pg_result, 0, sizeof(pg_result));
    if (auth_pg_lookup(login, node, &pg_result) > 0) {
	if (auth_verify_password(pg_result.password, plain)
	    && auth_nets_permit(pg_result.allow_nets, rip)) {
	    ok = 1;
	    *auth_user = mystrdup(login);
	}
	auth_cred_cache_store(login, node, ok);
	auth_pg_result_free(&pg_result);
	return (ok);
    }
    auth_pg_result_free(&pg_result);

    if (auth_ldap_authenticate(login, plain)) {
	*auth_user = mystrdup(login);
	return (1);
    }
    return (0);
}

static void auth_parse_kv(char *line, AUTH_SESSION *sess)
{
    char   *next;

    for (; line != 0; line = next) {
	next = split_at(line, '\t');
	if (strncmp(line, "service=", 8) == 0)
	    sess->service = mystrdup(line + 8);
	else if (strncmp(line, "node=", 5) == 0)
	    sess->node = mystrdup(line + 5);
	else if (strncmp(line, "lip=", 4) == 0)
	    sess->lip = mystrdup(line + 4);
	else if (strncmp(line, "rip=", 4) == 0)
	    sess->rip = mystrdup(line + 4);
	else if (strncmp(line, "resp=", 5) == 0) {
	    if (sess->mechanism && strcasecmp(sess->mechanism, "PLAIN") == 0)
		(void) auth_parse_plain_credentials(line + 5,
						    &sess->username,
						    &sess->password);
	}
    }
}

static void auth_handle_auth(VSTREAM *stream, char *line, AUTH_SESSION **sess_list)
{
    char   *id_str;
    char   *mech;
    AUTH_SESSION *sess;
    char   *auth_user = 0;
    unsigned int id;

    id_str = line;
    line = split_at(line, '\t');
    mech = line;
    line = split_at(line, '\t');

    id = (unsigned int) strtoul(id_str, 0, 10);
    sess = (AUTH_SESSION *) mymalloc(sizeof(*sess));
    memset((void *) sess, 0, sizeof(*sess));
    sess->request_id = id;
    sess->mechanism = mystrdup(mech ? mech : "");
    auth_parse_kv(line, sess);

    if (strcasecmp(sess->mechanism, "LOGIN") == 0 && sess->username == 0) {
	sess->next = *sess_list;
	*sess_list = sess;
	auth_reply_cont(stream, id, "VXNlcm5hbWU6");
	return;
    }

    if (sess->username && sess->password) {
	if (auth_perform(sess->username, sess->password,
			 sess->node, sess->rip, &auth_user))
	    auth_reply_ok(stream, id, auth_user);
	else
	    auth_reply_fail(stream, id, "authentication failed");
	if (auth_user)
	    myfree(auth_user);
	auth_session_free(sess);
	return;
    }

    auth_reply_fail(stream, id, "malformed authentication credentials");
    auth_session_free(sess);
}

static void auth_handle_cont(VSTREAM *stream, char *line, AUTH_SESSION **sess_list)
{
    char   *id_str;
    char   *payload;
    unsigned int id;
    AUTH_SESSION *sess;
    VSTRING *raw = vstring_alloc(32);
    char   *auth_user = 0;

    id_str = line;
    line = split_at(line, '\t');
    payload = line ? line : "";
    id = (unsigned int) strtoul(id_str, 0, 10);

    sess = auth_session_get(sess_list, id);
    if (sess == 0) {
	auth_reply_fail(stream, id, "unexpected CONT");
	vstring_free(raw);
	return;
    }

    if (base64_decode(raw, payload, (ssize_t) strlen(payload)) <= 0) {
	auth_reply_fail(stream, id, "malformed base64");
	auth_session_unlink(sess_list, sess);
	auth_session_free(sess);
	vstring_free(raw);
	return;
    }

    if (sess->username == 0) {
	sess->username = mystrdup(vstring_str(raw));
	auth_reply_cont(stream, id, "UGFzc3dvcmQ6");
	vstring_free(raw);
	return;
    }

    sess->password = mystrdup(vstring_str(raw));
    vstring_free(raw);
    if (auth_perform(sess->username, sess->password,
		     sess->node, sess->rip, &auth_user))
	auth_reply_ok(stream, id, auth_user);
    else
	auth_reply_fail(stream, id, "authentication failed");
    if (auth_user)
	myfree(auth_user);
    auth_session_unlink(sess_list, sess);
    auth_session_free(sess);
}

static void auth_service(VSTREAM *stream, char *service, char **argv)
{
    VSTRING *buf = vstring_alloc(256);
    char   *line;
    char   *cmd;
    AUTH_SESSION *sess_list = 0;
    AUTH_SESSION *sess;
    AUTH_SESSION *next;

    (void) service;
    (void) argv;

    while (vstring_get_nonl(buf, stream) != VSTREAM_EOF) {
	line = vstring_str(buf);
	cmd = line;
	line = split_at(line, '\t');
	if (strcmp(cmd, "AUTH") == 0)
	    auth_handle_auth(stream, line, &sess_list);
	else if (strcmp(cmd, "CONT") == 0)
	    auth_handle_cont(stream, line, &sess_list);
    }
    for (sess = sess_list; sess != 0; sess = next) {
	next = sess->next;
	auth_session_free(sess);
    }
    vstring_free(buf);
}

static void auth_sig_hup(int unused_sig)
{
    (void) unused_sig;
    auth_ldap_chain_reload();
    auth_cred_cache_flush();
}

static void post_jail_init(char *unused_name, char **unused_argv)
{
    (void) unused_name;
    (void) unused_argv;

    signal(SIGHUP, auth_sig_hup);
    mail_dict_init();
    cryptmaps_init();
    if (*var_auth_authenticate_maps != 0
	&& auth_pg_init() < 0)
	msg_warn("auth: auth_authenticate_maps init failed");
    auth_ldap_chain_reload();
    var_use_limit = 0;
}

static void auth_exit(char *unused_name, char **unused_argv)
{
    (void) unused_name;
    (void) unused_argv;
    auth_pg_shutdown();
    auth_cred_cache_flush();
}

MAIL_VERSION_STAMP_DECLARE;

int     main(int argc, char **argv)
{
    MAIL_VERSION_STAMP_ALLOCATE;

    single_server_main(argc, argv, auth_service,
		       CA_MAIL_SERVER_STR_TABLE(str_table),
		       CA_MAIL_SERVER_INT_TABLE(int_table),
		       CA_MAIL_SERVER_POST_INIT(post_jail_init),
		       CA_MAIL_SERVER_EXIT(auth_exit),
		       0);
}
