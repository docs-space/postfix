/*++
/* NAME
/*	postapi 8
/* SUMMARY
/*	Postfix HTTP API daemon
/* SYNOPSIS
/*	\fBpostapi\fR [generic Postfix daemon options]
/* DESCRIPTION
/*	The postapi(8) daemon is a single-process Postfix service
/*	that serves JSON over HTTP or HTTPS using GNU libmicrohttpd,
/*	validates \fBAuthorization: Bearer\fR tokens against Postfix
/*	lookup tables (including \fBproxy:\fR dynamicmaps), and exposes
/*	\fB/api/v1\fR for GET, POST, PUT, PATCH and DELETE.
/*--*/

#include <sys_defs.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <microhttpd.h>
#include <jansson.h>

#include <mail_version.h>
#include <mail_server.h>
#include <mail_params.h>
#include <msg.h>
#include <mymalloc.h>
#include <dict.h>
#include <maps.h>
#include <vstream.h>
#include <vstring.h>

#ifdef USE_TLS
#include <tls.h>
#include <gnutls/gnutls.h>
#endif

#define POSTAPI_API_PREFIX	"/api/v1"
#define POSTAPI_MAX_BODY	(1024 * 1024)

static const char postapi_tls_cert_file_param[] = "postapi_tls_cert_file";
static const char postapi_tls_key_file_param[] = "postapi_tls_key_file";
static const char postapi_tls_level_param[] = "postapi_tls_security_level";
static const char postapi_tls_loglevel_param[] = "postapi_tls_loglevel";
static const char postapi_tls_scache_db_param[] = "postapi_tls_session_cache_database";
static const char postapi_tls_scache_timeout_param[] = "postapi_tls_session_cache_timeout";
static const char postapi_starttls_timeout_param[] = "postapi_starttls_timeout";
static const char postapi_access_token_maps_param[] = "postapi_access_token_maps";

static char *var_postapi_tls_cert_file;
static char *var_postapi_tls_key_file;
static char *var_postapi_tls_level;
static char *var_postapi_tls_loglevel;
static char *var_postapi_tls_scache_db;
static int var_postapi_tls_scache_timeout;
static int var_postapi_starttls_tmout;
static char *var_postapi_access_token_maps;

static int postapi_use_tls;
static MAPS *postapi_token_maps;
static struct MHD_Daemon *postapi_mhd;

#ifdef USE_TLS
static gnutls_datum_t postapi_tls_key_pem;
static gnutls_datum_t postapi_tls_cert_pem;
#endif

static const CONFIG_STR_TABLE str_table[] = {
    postapi_tls_cert_file_param, "", &var_postapi_tls_cert_file, 0, 0,
    postapi_tls_key_file_param, "", &var_postapi_tls_key_file, 0, 0,
    postapi_tls_level_param, "none", &var_postapi_tls_level, 0, 0,
    postapi_tls_loglevel_param, "0", &var_postapi_tls_loglevel, 0, 0,
    postapi_tls_scache_db_param, "btree:${data_directory}/postapi_scache", &var_postapi_tls_scache_db, 0, 0,
    postapi_access_token_maps_param, "", &var_postapi_access_token_maps, 0, 0,
    0,
};

static const CONFIG_TIME_TABLE time_table[] = {
    postapi_starttls_timeout_param, "300s", &var_postapi_starttls_tmout, 1, 0,
    postapi_tls_scache_timeout_param, "3600s", &var_postapi_tls_scache_timeout, 1, 8640000,
    0,
};

 /*
  * Per-request state for libmicrohttpd upload accumulation.
  */
typedef struct {
    VSTRING *body;
    int     overflow;
} POSTAPI_REQ;

 /* postapi_req_free - release request context */

static void postapi_req_free(void *ptr)
{
    POSTAPI_REQ *req = (POSTAPI_REQ *) ptr;

    if (req == 0)
	return;
    if (req->body)
	vstring_free(req->body);
    myfree(req);
}

 /* postapi_mhd_notify - free connection context when the connection ends */

static void
postapi_mhd_notify(void *cls, struct MHD_Connection *connection,
		   void **con_cls,
		   enum MHD_ConnectionNotificationCode toe)
{
    (void) cls;
    (void) connection;
    (void) toe;

    if (con_cls == 0 || *con_cls == 0)
	return;
    postapi_req_free(*con_cls);
    *con_cls = 0;
}

 /* postapi_json_reply - queue JSON response, free json object */

static enum MHD_Result
postapi_json_reply(struct MHD_Connection *connection, unsigned int code,
		   json_t *obj)
{
    struct MHD_Response *resp;
    char   *dump;
    size_t  len;
    enum MHD_Result q;

    if (obj == 0)
	return MHD_NO;
    dump = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (dump == 0)
	return MHD_NO;
    len = strlen(dump);
    resp = MHD_create_response_from_buffer(len, dump, MHD_RESPMEM_MUST_FREE);
    if (resp == 0) {
	free(dump);
	return MHD_NO;
    }
    (void) MHD_add_response_header(resp, "Content-Type", "application/json; charset=utf-8");
    (void) MHD_add_response_header(resp, "Connection", "close");
    q = MHD_queue_response(connection, code, resp);
    MHD_destroy_response(resp);
    return q;
}

 /* postapi_bearer_token - parse Authorization: Bearer <token> */

static const char *postapi_bearer_token(const char *auth)
{
    const char *cp;

    if (auth == 0)
	return (0);
    while (*auth == ' ' || *auth == '\t')
	auth++;
    if (strncasecmp(auth, "Bearer", 6) != 0)
	return (0);
    cp = auth + 6;
    if (*cp != ' ' && *cp != '\t')
	return (0);
    while (*cp == ' ' || *cp == '\t')
	cp++;
    if (*cp == 0)
	return (0);
    return (cp);
}

 /* postapi_auth_ok - validate bearer token against access token maps */

static int postapi_auth_ok(const char *token)
{
    const char *exp;

    if (postapi_token_maps == 0)
	return (0);
    exp = maps_find(postapi_token_maps, token, 0);
    if (exp != 0)
	return (1);
    return (0);
}

 /* postapi_access_handler - libmicrohttpd callback */

static enum MHD_Result
postapi_access_handler(void *cls, struct MHD_Connection *connection,
		       const char *url, const char *method,
		       const char *version, const char *upload_data,
		       size_t *upload_data_size, void **con_cls)
{
    POSTAPI_REQ *req;
    const char *auth_hdr;
    const char *token;
    const char *ctype;
    json_t *out;
    json_t *body_json = 0;
    json_error_t jerr;
    int     is_mutating;

    (void) cls;
    (void) version;

    if (*con_cls == 0) {
	req = (POSTAPI_REQ *) mymalloc(sizeof(*req));
	req->body = vstring_alloc(256);
	req->overflow = 0;
	*con_cls = req;
	return MHD_YES;
    }
    req = (POSTAPI_REQ *) *con_cls;

    if (*upload_data_size > 0) {
	if (req->overflow) {
	    *upload_data_size = 0;
	    return MHD_YES;
	}
	if (VSTRING_LEN(req->body) + *upload_data_size > POSTAPI_MAX_BODY) {
	    req->overflow = 1;
	    *upload_data_size = 0;
	    return postapi_json_reply(connection, 413,
				      json_pack("{s:s}", "error", "payload too large"));
	}
	vstring_strncat(req->body, upload_data, (ssize_t) *upload_data_size);
	*upload_data_size = 0;
	return MHD_YES;
    }

    /*
     * Dispatch by URL prefix.
     */
    if (strncmp(url, POSTAPI_API_PREFIX, sizeof(POSTAPI_API_PREFIX) - 1) != 0) {
	return postapi_json_reply(connection, 404,
				    json_pack("{s:s,s:s}", "error", "not_found",
					      "path", url));
    }

    /*
     * Authorization: Bearer <access_token> only (no other schemes).
     */
    auth_hdr = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
					   "Authorization");
    token = postapi_bearer_token(auth_hdr);
    if (token == 0) {
	return postapi_json_reply(connection, 401,
				    json_pack("{s:s}", "error",
					      "missing_or_invalid_authorization"));
    }
    if (postapi_auth_ok(token) == 0) {
	if (postapi_token_maps && postapi_token_maps->error != 0)
	    return postapi_json_reply(connection, 503,
					json_pack("{s:s}", "error",
						  "token_lookup_failed"));
	return postapi_json_reply(connection, 401,
				  json_pack("{s:s}", "error", "invalid_token"));
    }

    /*
     * JSON body for methods that usually carry a body.
     */
    is_mutating = (strcmp(method, "POST") == 0
		   || strcmp(method, "PUT") == 0
		   || strcmp(method, "PATCH") == 0);
    if (is_mutating) {
	ctype = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
					    "Content-Type");
	if (ctype == 0 || strncasecmp(ctype, "application/json", 16) != 0) {
	    return postapi_json_reply(connection, 415,
					json_pack("{s:s}", "error",
						  "content_type_must_be_application_json"));
	}
	if (VSTRING_LEN(req->body) > 0) {
	    body_json = json_loads(vstring_str(req->body), 0, &jerr);
	    if (body_json == 0) {
		return postapi_json_reply(connection, 400,
					  json_pack("{s:s,s:s}", "error",
						    "invalid_json",
						    "detail", jerr.text));
	    }
	} else {
	    body_json = json_object();
	}
    }

    if (strcmp(method, "GET") != 0
	&& strcmp(method, "POST") != 0
	&& strcmp(method, "PUT") != 0
	&& strcmp(method, "PATCH") != 0
	&& strcmp(method, "DELETE") != 0) {
	if (body_json)
	    json_decref(body_json);
	return postapi_json_reply(connection, 405,
				  json_pack("{s:s,s:s}", "error", "method_not_allowed",
					    "allow", "GET, POST, PUT, PATCH, DELETE"));
    }

    out = json_pack("{s:s,s:s,s:s}", "path", url, "method", method,
		    "api", "v1");
    if (out == 0) {
	if (body_json)
	    json_decref(body_json);
	return postapi_json_reply(connection, 500,
				  json_pack("{s:s}", "error", "out_of_memory"));
    }
    if (body_json)
	json_object_set_new(out, "body", body_json);

    return postapi_json_reply(connection, 200, out);
}

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
    uint64_t mhd_flags = (uint64_t) MHD_USE_NO_LISTEN_SOCKET;

    (void) unused_name;
    (void) unused_argv;

#ifdef USE_TLS
    {
	int     tls_level;

	tls_level = tls_level_lookup(var_postapi_tls_level);
	if (tls_level == TLS_LEV_INVALID || tls_level == TLS_LEV_NOTFOUND)
	    msg_fatal("invalid %s value: %s",
		      postapi_tls_level_param, var_postapi_tls_level);
	postapi_use_tls = (tls_level != TLS_LEV_NONE);

	if (postapi_use_tls) {
	    if (*var_postapi_tls_cert_file == 0)
		msg_fatal("%s is empty while TLS is enabled",
			  postapi_tls_cert_file_param);
	    if (*var_postapi_tls_key_file == 0)
		msg_fatal("%s is empty while TLS is enabled",
			  postapi_tls_key_file_param);
#ifdef MHD_USE_TLS
	    mhd_flags |= (uint64_t) MHD_USE_TLS;
#else
	    msg_fatal("libmicrohttpd lacks MHD_USE_TLS; rebuild microhttpd with HTTPS");
#endif
	}
    }
#else
    if (strcasecmp(var_postapi_tls_level, "none") != 0)
	msg_fatal("%s=%s but Postfix was built without TLS support",
		  postapi_tls_level_param, var_postapi_tls_level);
    postapi_use_tls = 0;
#endif

    if (*var_postapi_access_token_maps == 0)
	msg_fatal("%s must be set (example: proxy:pgsql:/etc/postfix/...)",
		  postapi_access_token_maps_param);

    postapi_token_maps = maps_create("postapi access token",
				     var_postapi_access_token_maps,
				     DICT_FLAG_LOCK | DICT_FLAG_FOLD_FIX);

    if (postapi_use_tls) {
#ifdef USE_TLS
	int     gerr;

	if (gnutls_global_init() != 0)
	    msg_fatal("gnutls_global_init failed");
	gerr = gnutls_load_file(var_postapi_tls_key_file, &postapi_tls_key_pem);
	if (gerr < 0)
	    msg_fatal("gnutls_load_file(%s): %s", var_postapi_tls_key_file,
		      gnutls_strerror(gerr));
	gerr = gnutls_load_file(var_postapi_tls_cert_file, &postapi_tls_cert_pem);
	if (gerr < 0)
	    msg_fatal("gnutls_load_file(%s): %s", var_postapi_tls_cert_file,
		      gnutls_strerror(gerr));
	postapi_mhd = MHD_start_daemon(mhd_flags, 0,
				       0, 0,
				       &postapi_access_handler, 0,
				       MHD_OPTION_HTTPS_MEM_KEY,
				       (const char *) postapi_tls_key_pem.data,
				       MHD_OPTION_HTTPS_MEM_CERT,
				       (const char *) postapi_tls_cert_pem.data,
				       MHD_OPTION_NOTIFY_COMPLETED,
				       postapi_mhd_notify, 0,
				       MHD_OPTION_END);
#else
	msg_fatal("internal error: TLS enabled without USE_TLS");
#endif
    } else {
	postapi_mhd = MHD_start_daemon(mhd_flags, 0,
				       0, 0,
				       &postapi_access_handler, 0,
				       MHD_OPTION_NOTIFY_COMPLETED,
				       postapi_mhd_notify, 0,
				       MHD_OPTION_END);
    }
    if (postapi_mhd == 0)
	msg_fatal("cannot start libmicrohttpd daemon for postapi");
}

static void postapi_service(VSTREAM *client_stream, char *service, char **argv)
{
    int     base_fd;
    int     conn_fd;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    time_t  deadline;
    const union MHD_DaemonInfo *dinfo;

    (void) service;

    if (argv[0])
	msg_fatal("unexpected command-line argument: %s", argv[0]);

    base_fd = vstream_fileno(client_stream);
    conn_fd = dup(base_fd);
    if (conn_fd < 0)
	msg_fatal("dup(postapi client socket): %m");

    peer_len = (socklen_t) sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    if (getpeername(base_fd, (struct sockaddr *) &peer, &peer_len) < 0) {
	peer_len = 0;
	if (MHD_add_connection(postapi_mhd, conn_fd, 0, 0) != MHD_YES)
	    msg_fatal("MHD_add_connection: failed");
    } else {
	if (MHD_add_connection(postapi_mhd, conn_fd,
			       (const struct sockaddr *) &peer,
			       peer_len) != MHD_YES)
	    msg_fatal("MHD_add_connection: failed");
    }

    deadline = time((time_t *) 0)
	+ (var_postapi_starttls_tmout > 0 ? var_postapi_starttls_tmout : 300);
    if (deadline < time((time_t *) 0) + 30)
	deadline = time((time_t *) 0) + 30;

    for (;;) {
	(void) MHD_run(postapi_mhd);
	dinfo = MHD_get_daemon_info(postapi_mhd,
				    MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
	if (dinfo == 0 || dinfo->num_connections == 0)
	    break;
	if (time((time_t *) 0) > deadline) {
	    msg_warn("postapi: MHD connection timed out, closing fd");
	    (void) close(conn_fd);
	    break;
	}
    }
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
