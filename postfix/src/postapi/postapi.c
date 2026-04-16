/*++
/* NAME
/*	postapi 8
/* SUMMARY
/*	Postfix HTTP API daemon (prototype)
/* SYNOPSIS
/*	\fBpostapi\fR [generic Postfix daemon options]
/* DESCRIPTION
/*	The postapi(8) daemon is a single-process Postfix service
/*	skeleton that accepts a client connection and returns a minimal
/*	HTTP/1.1 JSON response.
/*--*/

#include <sys_defs.h>
#include <string.h>
#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <mail_version.h>
#include <mail_server.h>
#include <mail_params.h>
#include <msg.h>
#include <vstream.h>
#include <vstring.h>

#ifdef USE_TLS
#include <tls.h>
#endif

static const char postapi_tls_cert_file_param[] = "postapi_tls_cert_file";
static const char postapi_tls_key_file_param[] = "postapi_tls_key_file";
static const char postapi_tls_level_param[] = "postapi_tls_security_level";
static const char postapi_tls_loglevel_param[] = "postapi_tls_loglevel";
static const char postapi_tls_scache_db_param[] = "postapi_tls_session_cache_database";
static const char postapi_tls_scache_timeout_param[] = "postapi_tls_session_cache_timeout";
static const char postapi_starttls_timeout_param[] = "postapi_starttls_timeout";

static char *var_postapi_tls_cert_file;
static char *var_postapi_tls_key_file;
static char *var_postapi_tls_level;
static char *var_postapi_tls_loglevel;
static char *var_postapi_tls_scache_db;
static int var_postapi_tls_scache_timeout;
static int var_postapi_starttls_tmout;

#ifdef USE_TLS
static TLS_APPL_STATE *postapi_tls_ctx;
#endif
static int postapi_use_tls;

static const CONFIG_STR_TABLE str_table[] = {
    postapi_tls_cert_file_param, "", &var_postapi_tls_cert_file, 0, 0,
    postapi_tls_key_file_param, "", &var_postapi_tls_key_file, 0, 0,
    postapi_tls_level_param, "none", &var_postapi_tls_level, 0, 0,
    postapi_tls_loglevel_param, "0", &var_postapi_tls_loglevel, 0, 0,
    postapi_tls_scache_db_param, "btree:${data_directory}/postapi_scache", &var_postapi_tls_scache_db, 0, 0,
    0,
};

static const CONFIG_TIME_TABLE time_table[] = {
    postapi_starttls_timeout_param, "300s", &var_postapi_starttls_tmout, 1, 0,
    postapi_tls_scache_timeout_param, "3600s", &var_postapi_tls_scache_timeout, 1, 8640000,
    0,
};

static void postapi_pre_accept(char *unused_name, char **unused_argv)
{
    (void) unused_name;
    (void) unused_argv;

    if (dict_changed_name() != 0) {
	msg_info("postapi config changed - restarting");
	exit(0);
    }
}

static void postapi_post_init(char *unused_name, char **unused_argv)
{
    (void) unused_name;
    (void) unused_argv;

#ifdef USE_TLS
    TLS_SERVER_INIT_PROPS props;
    int tls_level;

    tls_level = tls_level_lookup(var_postapi_tls_level);
    if (tls_level == TLS_LEV_INVALID || tls_level == TLS_LEV_NOTFOUND)
	msg_fatal("invalid %s value: %s",
		  postapi_tls_level_param, var_postapi_tls_level);
    postapi_use_tls = (tls_level != TLS_LEV_NONE);

    if (postapi_use_tls == 0)
	return;

    if (*var_postapi_tls_cert_file == 0)
	msg_fatal("%s is empty while TLS is enabled",
		  postapi_tls_cert_file_param);
    if (*var_postapi_tls_key_file == 0)
	msg_fatal("%s is empty while TLS is enabled",
		  postapi_tls_key_file_param);

    tls_pre_jail_init(TLS_ROLE_SERVER);

    postapi_tls_ctx =
	TLS_SERVER_INIT(&props,
			log_param = postapi_tls_loglevel_param,
			log_level = var_postapi_tls_loglevel,
			verifydepth = 1,
			cache_type = TLS_MGR_SCACHE_POSTAPI,
			set_sessid = 1,
			chain_files = "",
			cert_file = var_postapi_tls_cert_file,
			key_file = var_postapi_tls_key_file,
			dcert_file = "",
			dkey_file = "",
			eccert_file = "",
			eckey_file = "",
			CAfile = "",
			CApath = "",
			protocols = "",
			eecdh_grade = "auto",
			dh1024_param_file = "",
			dh512_param_file = "",
			ask_ccert = 0,
			mdalg = "sha256");
    if (postapi_tls_ctx == 0)
	msg_fatal("cannot initialize TLS context for postapi");
#else
    if (strcasecmp(var_postapi_tls_level, "none") != 0)
	msg_fatal("%s=%s but Postfix was built without TLS support",
		  postapi_tls_level_param, var_postapi_tls_level);
    postapi_use_tls = 0;
#endif
}

static void postapi_service(VSTREAM *client_stream, char *service, char **argv)
{
    VSTRING *request_line = vstring_alloc(256);
#ifdef USE_TLS
    TLS_SESS_STATE *tls_context = 0;
    TLS_SERVER_START_PROPS props;
#endif

    if (argv[0])
	msg_fatal("unexpected command-line argument: %s", argv[0]);

#ifdef USE_TLS
    if (postapi_use_tls) {
	tls_context =
	    TLS_SERVER_START(&props,
			     ctx = postapi_tls_ctx,
			     stream = client_stream,
			     fd = -1,
			     timeout = var_postapi_starttls_tmout,
			     enable_rpk = 0,
			     requirecert = 0,
			     serverid = service,
			     namaddr = "postapi-client",
			     cipher_grade = "medium",
			     cipher_exclusions = "",
			     mdalg = "sha256");
	if (tls_context == 0) {
	    msg_warn("postapi TLS handshake failed");
	    vstring_free(request_line);
	    return;
	}
    }
#endif

    if (vstring_get_nonl(request_line, client_stream) != VSTREAM_EOF)
	msg_info("postapi request: %s", vstring_str(request_line));

    vstream_fprintf(client_stream,
		    "HTTP/1.1 200 OK\r\n"
		    "Content-Type: application/json\r\n"
		    "Connection: close\r\n"
		    "\r\n"
		    "{\"service\":\"postapi\",\"status\":\"ok\"}\n");
    vstream_fflush(client_stream);

#ifdef USE_TLS
    if (tls_context != 0)
	tls_server_stop(postapi_tls_ctx, client_stream,
			var_postapi_starttls_tmout, 0, tls_context);
#endif
    vstring_free(request_line);
}

MAIL_VERSION_STAMP_DECLARE;

int     main(int argc, char **argv)
{
    MAIL_VERSION_STAMP_ALLOCATE;

    single_server_main(argc, argv, postapi_service,
		       CA_MAIL_SERVER_STR_TABLE(str_table),
		       CA_MAIL_SERVER_TIME_TABLE(time_table),
		       CA_MAIL_SERVER_POST_INIT(postapi_post_init),
		       CA_MAIL_SERVER_PRE_ACCEPT(postapi_pre_accept),
		       0);
}
