/*++
/* NAME
/*	xsasl_internal_server 3
/* SUMMARY
/*	Postfix auth daemon SASL server-side plug-in
/* SYNOPSIS
/*	XSASL_SERVER_IMPL *xsasl_internal_server_init(server_type, path_info)
/*	const char *server_type;
/*	const char *path_info;
/*--*/

#include <sys_defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <msg.h>
#include <mymalloc.h>
#include <connect.h>
#include <split_at.h>
#include <stringops.h>
#include <vstream.h>
#include <vstring_vstream.h>
#include <name_mask.h>
#include <argv.h>
#include <myaddrinfo.h>

#include <mail_params.h>

#include <xsasl.h>
#include <xsasl_internal.h>

#if defined(USE_SASL_AUTH) && defined(USE_INTERNAL_SASL)

#define AUTH_TIMEOUT	10

#define SEC_PROPS_NOPLAINTEXT	(1 << 0)
#define SEC_PROPS_NOACTIVE	(1 << 1)
#define SEC_PROPS_NODICTIONARY	(1 << 2)
#define SEC_PROPS_NOANONYMOUS	(1 << 3)
#define SEC_PROPS_FWD_SECRECY	(1 << 4)
#define SEC_PROPS_MUTUAL_AUTH	(1 << 5)

#define SEC_PROPS_POS_MASK	(SEC_PROPS_MUTUAL_AUTH | SEC_PROPS_FWD_SECRECY)
#define SEC_PROPS_NEG_MASK	(SEC_PROPS_NOPLAINTEXT | SEC_PROPS_NOACTIVE | \
				SEC_PROPS_NODICTIONARY | SEC_PROPS_NOANONYMOUS)

static const NAME_MASK xsasl_internal_conf_sec_props[] = {
    "noplaintext", SEC_PROPS_NOPLAINTEXT,
    "noactive", SEC_PROPS_NOACTIVE,
    "nodictionary", SEC_PROPS_NODICTIONARY,
    "noanonymous", SEC_PROPS_NOANONYMOUS,
    "forward_secrecy", SEC_PROPS_FWD_SECRECY,
    "mutual_auth", SEC_PROPS_MUTUAL_AUTH,
    0, 0,
};

typedef struct {
    XSASL_SERVER_IMPL xsasl;
    VSTREAM *sasl_stream;
    char   *socket_path;
    unsigned int request_id_counter;
} XSASL_INTERNAL_SERVER_IMPL;

typedef struct {
    XSASL_SERVER xsasl;
    XSASL_INTERNAL_SERVER_IMPL *impl;
    unsigned int last_request_id;
    char   *service;
    char   *username;
    VSTRING *sasl_line;
    unsigned int sec_props;
    int     tls_flag;
    char   *mechanism_list;
    ARGV   *mechanism_argv;
    char   *client_addr;
    char   *server_addr;
} XSASL_INTERNAL_SERVER;

static void xsasl_internal_server_done(XSASL_SERVER_IMPL *);
static XSASL_SERVER *xsasl_internal_server_create(XSASL_SERVER_IMPL *,
					        XSASL_SERVER_CREATE_ARGS *);
static void xsasl_internal_server_free(XSASL_SERVER *);
static int xsasl_internal_server_first(XSASL_SERVER *, const char *,
				              const char *, VSTRING *);
static int xsasl_internal_server_next(XSASL_SERVER *, const char *, VSTRING *);
static const char *xsasl_internal_server_get_mechanism_list(XSASL_SERVER *);
static const char *xsasl_internal_server_get_username(XSASL_SERVER *);

static void xsasl_internal_server_disconnect(XSASL_INTERNAL_SERVER_IMPL *xp)
{
    if (xp->sasl_stream) {
	(void) vstream_fclose(xp->sasl_stream);
	xp->sasl_stream = 0;
    }
}

static int xsasl_internal_server_connect(XSASL_INTERNAL_SERVER_IMPL *xp)
{
    const char *myname = "xsasl_internal_server_connect";
    int     fd;
    const char *path;

    if (xp->sasl_stream)
	return (0);

    if (msg_verbose)
	msg_info("%s: connecting to %s", myname, xp->socket_path);

    path = xp->socket_path;
    if (strncmp(path, "inet:", 5) == 0) {
	fd = inet_connect(path + 5, BLOCKING, AUTH_TIMEOUT);
    } else {
	if (strncmp(path, "unix:", 5) == 0)
	    path += 5;
	fd = unix_connect(path, BLOCKING, AUTH_TIMEOUT);
    }
    if (fd < 0) {
	msg_warn("SASL: connect to auth socket '%s' failed: %m",
		 xp->socket_path);
	return (-1);
    }
    xp->sasl_stream = vstream_fdopen(fd, O_RDWR);
    vstream_control(xp->sasl_stream,
		    CA_VSTREAM_CTL_PATH(xp->socket_path),
		    CA_VSTREAM_CTL_TIMEOUT(AUTH_TIMEOUT),
		    CA_VSTREAM_CTL_END);
    return (0);
}

static char *xsasl_internal_build_mech_list(ARGV *mechanism_argv,
					            unsigned int conf_props)
{
    VSTRING *mechanisms_str = vstring_alloc(10);
    static const struct {
	const char *name;
	unsigned int sec_props;
    } mechs[] = {
	{"PLAIN", SEC_PROPS_NOPLAINTEXT},
	{"LOGIN", SEC_PROPS_NOPLAINTEXT},
	{0, 0},
    };
    unsigned int pos_conf_props = (conf_props & SEC_PROPS_POS_MASK);
    unsigned int neg_conf_props = (conf_props & SEC_PROPS_NEG_MASK);
    int     i;

    for (i = 0; mechs[i].name != 0; i++) {
	if ((mechs[i].sec_props & pos_conf_props) == pos_conf_props
	    && (mechs[i].sec_props & neg_conf_props) == 0) {
	    if (VSTRING_LEN(mechanisms_str) > 0)
		VSTRING_ADDCH(mechanisms_str, ' ');
	    vstring_strcat(mechanisms_str, mechs[i].name);
	    argv_add(mechanism_argv, mechs[i].name, (char *) 0);
	}
    }
    return (vstring_export(mechanisms_str));
}

XSASL_SERVER_IMPL *xsasl_internal_server_init(const char *server_type,
				              const char *path_info)
{
    XSASL_INTERNAL_SERVER_IMPL *xp;

    (void) server_type;
    xp = (XSASL_INTERNAL_SERVER_IMPL *)
	mymalloc(sizeof(*xp));
    xp->xsasl.create = xsasl_internal_server_create;
    xp->xsasl.done = xsasl_internal_server_done;
    xp->socket_path = mystrdup(path_info);
    xp->sasl_stream = 0;
    xp->request_id_counter = 0;
    return (&xp->xsasl);
}

static void xsasl_internal_server_done(XSASL_SERVER_IMPL *impl)
{
    XSASL_INTERNAL_SERVER_IMPL *xp = (XSASL_INTERNAL_SERVER_IMPL *) impl;

    xsasl_internal_server_disconnect(xp);
    myfree(xp->socket_path);
    myfree((void *) impl);
}

static XSASL_SERVER *xsasl_internal_server_create(XSASL_SERVER_IMPL *impl,
				             XSASL_SERVER_CREATE_ARGS *args)
{
    const char *myname = "xsasl_internal_server_create";
    XSASL_INTERNAL_SERVER *server;
    struct sockaddr_storage ss;
    struct sockaddr *sa = (struct sockaddr *) &ss;
    SOCKADDR_SIZE salen;
    MAI_HOSTADDR_STR server_addr;

    if (msg_verbose)
	msg_info("%s: SASL service=%s, realm=%s",
		 myname, args->service, args->user_realm ?
		 args->user_realm : "(null)");

    server = (XSASL_INTERNAL_SERVER *) mymalloc(sizeof(*server));
    server->xsasl.free = xsasl_internal_server_free;
    server->xsasl.first = xsasl_internal_server_first;
    server->xsasl.next = xsasl_internal_server_next;
    server->xsasl.get_mechanism_list = xsasl_internal_server_get_mechanism_list;
    server->xsasl.get_username = xsasl_internal_server_get_username;
    server->impl = (XSASL_INTERNAL_SERVER_IMPL *) impl;
    server->sasl_line = vstring_alloc(256);
    server->username = 0;
    server->service = mystrdup(args->service);
    server->last_request_id = 0;
    server->mechanism_list = 0;
    server->mechanism_argv = 0;
    server->tls_flag = args->tls_flag;
    server->sec_props =
	name_mask_opt(myname, xsasl_internal_conf_sec_props,
		      args->security_options,
		      NAME_MASK_ANY_CASE | NAME_MASK_FATAL);
    server->client_addr = mystrdup(args->client_addr);

    if (args->server_addr && *args->server_addr) {
	server->server_addr = mystrdup(args->server_addr);
    } else {
	salen = sizeof(ss);
	if (getsockname(vstream_fileno(args->stream), sa, &salen) < 0
	    || sockaddr_to_hostaddr(sa, salen, &server_addr, 0, 0) != 0)
	    server_addr.buf[0] = 0;
	server->server_addr = mystrdup(server_addr.buf);
    }

    return (&server->xsasl);
}

static const char *xsasl_internal_server_get_mechanism_list(XSASL_SERVER *xp)
{
    XSASL_INTERNAL_SERVER *server = (XSASL_INTERNAL_SERVER *) xp;

    if (server->mechanism_list == 0) {
	server->mechanism_argv = argv_alloc(3);
	server->mechanism_list =
	    xsasl_internal_build_mech_list(server->mechanism_argv,
					   server->sec_props);
    }
    return (server->mechanism_list[0] ? server->mechanism_list : 0);
}

static void xsasl_internal_server_free(XSASL_SERVER *xp)
{
    XSASL_INTERNAL_SERVER *server = (XSASL_INTERNAL_SERVER *) xp;

    vstring_free(server->sasl_line);
    if (server->username)
	myfree(server->username);
    if (server->mechanism_list) {
	myfree(server->mechanism_list);
	argv_free(server->mechanism_argv);
    }
    myfree(server->service);
    myfree(server->server_addr);
    myfree(server->client_addr);
    myfree((void *) server);
}

static int xsasl_internal_parse_reply(XSASL_INTERNAL_SERVER *server, char **line)
{
    char   *id;

    if (*line == NULL) {
	msg_warn("SASL: protocol error");
	return (-1);
    }
    id = *line;
    *line = split_at(*line, '\t');
    if (strtoul(id, NULL, 0) != server->last_request_id)
	return (-1);
    return (0);
}

static void xsasl_internal_parse_reply_args(XSASL_INTERNAL_SERVER *server,
					         char *line, VSTRING *reply,
					           int success)
{
    char   *next;

    if (server->username) {
	myfree(server->username);
	server->username = 0;
    }
    VSTRING_RESET(reply);
    VSTRING_TERMINATE(reply);

    for (; line != NULL; line = next) {
	next = split_at(line, '\t');
	if (strncmp(line, "user=", 5) == 0) {
	    server->username = mystrdup(line + 5);
	    printable(server->username, '?');
	} else if (strncmp(line, "reason=", 7) == 0) {
	    if (!success) {
		printable(line + 7, '?');
		vstring_strcpy(reply, line + 7);
	    }
	}
    }
}

static int xsasl_internal_handle_reply(XSASL_INTERNAL_SERVER *server,
				               VSTRING *reply)
{
    const char *myname = "xsasl_internal_handle_reply";
    char   *line, *cmd;

    while (vstring_get_nonl(server->sasl_line,
			    server->impl->sasl_stream) != VSTREAM_EOF) {
	line = vstring_str(server->sasl_line);

	if (msg_verbose)
	    msg_info("%s: auth reply: %s", myname, line);

	cmd = line;
	line = split_at(line, '\t');

	if (strcmp(cmd, "OK") == 0) {
	    if (xsasl_internal_parse_reply(server, &line) == 0) {
		xsasl_internal_parse_reply_args(server, line, reply, 1);
		if (server->username == 0) {
		    msg_warn("missing auth server %s username field", cmd);
		    vstring_strcpy(reply, "Authentication backend error");
		    return XSASL_AUTH_FAIL;
		}
		return XSASL_AUTH_DONE;
	    }
	} else if (strcmp(cmd, "CONT") == 0) {
	    if (xsasl_internal_parse_reply(server, &line) == 0) {
		vstring_strcpy(reply, line ? line : "");
		return XSASL_AUTH_MORE;
	    }
	} else if (strcmp(cmd, "FAIL") == 0) {
	    if (xsasl_internal_parse_reply(server, &line) == 0) {
		xsasl_internal_parse_reply_args(server, line, reply, 0);
		if (VSTRING_LEN(reply) == 0)
		    vstring_strcpy(reply, "Authentication failed");
		return XSASL_AUTH_FAIL;
	    }
	} else if (strcmp(cmd, "DONE") == 0) {
	    return XSASL_AUTH_DONE;
	}
    }
    vstring_strcpy(reply, "Connection lost to authentication server");
    xsasl_internal_server_disconnect(server->impl);
    return XSASL_AUTH_TEMP;
}

static int is_valid_base64(const char *data)
{
    for (; *data != '\0'; data++) {
	if (!((*data >= '0' && *data <= '9') ||
	      (*data >= 'a' && *data <= 'z') ||
	      (*data >= 'A' && *data <= 'Z') ||
	      *data == '+' || *data == '/' || *data == '='))
	    return (0);
    }
    return (1);
}

static int xsasl_internal_server_first(XSASL_SERVER *xp, const char *sasl_method,
			          const char *init_response, VSTRING *reply)
{
    const char *myname = "xsasl_internal_server_first";
    XSASL_INTERNAL_SERVER *server = (XSASL_INTERNAL_SERVER *) xp;
    char  **cpp;
    int     i;
    const char *node;

#define IFELSE(e1,e2,e3) ((e1) ? (e2) : (e3))

    if (msg_verbose)
	msg_info("%s: sasl_method %s%s%s", myname, sasl_method,
		 IFELSE(init_response, ", init_response ", ""),
		 IFELSE(init_response, init_response, ""));

    if (server->mechanism_argv == 0)
	(void) xsasl_internal_server_get_mechanism_list(xp);

    for (cpp = server->mechanism_argv->argv; ; cpp++) {
	if (*cpp == 0) {
	    vstring_sprintf(reply, "Invalid authentication mechanism: '%s'",
			    sasl_method);
	    printable(vstring_str(reply), '?');
	    return XSASL_AUTH_FAIL;
	}
	if (strcasecmp(sasl_method, *cpp) == 0)
	    break;
    }
    if (init_response && !is_valid_base64(init_response)) {
	vstring_strcpy(reply, "Invalid base64 data in initial response");
	return XSASL_AUTH_FAIL;
    }

    node = (var_multi_name && *var_multi_name) ? var_multi_name : "";

    for (i = 0; i < 2; i++) {
	if (!server->impl->sasl_stream) {
	    if (xsasl_internal_server_connect(server->impl) < 0)
		return XSASL_AUTH_TEMP;
	}
	server->last_request_id = ++server->impl->request_id_counter;
	vstream_fprintf(server->impl->sasl_stream,
			"AUTH\t%u\t%s\tservice=%s\tnologin\tnode=%s\tlip=%s\trip=%s",
			server->last_request_id, sasl_method,
			server->service, node,
			server->server_addr, server->client_addr);
	if (server->tls_flag)
	    vstream_fputs("\tsecured", server->impl->sasl_stream);
	if (init_response)
	    vstream_fprintf(server->impl->sasl_stream,
			    "\tresp=%s", init_response);
	VSTREAM_PUTC('\n', server->impl->sasl_stream);

	if (vstream_fflush(server->impl->sasl_stream) != VSTREAM_EOF)
	    break;

	if (i == 1) {
	    vstring_strcpy(reply, "Can't connect to authentication server");
	    xsasl_internal_server_disconnect(server->impl);
	    return XSASL_AUTH_TEMP;
	}
	xsasl_internal_server_disconnect(server->impl);
    }

    return xsasl_internal_handle_reply(server, reply);
}

static int xsasl_internal_server_next(XSASL_SERVER *xp, const char *request,
				             VSTRING *reply)
{
    XSASL_INTERNAL_SERVER *server = (XSASL_INTERNAL_SERVER *) xp;

    if (!is_valid_base64(request)) {
	vstring_strcpy(reply, "Invalid base64 data in continued response");
	return XSASL_AUTH_FAIL;
    }
    vstream_fprintf(server->impl->sasl_stream,
		    "CONT\t%u\t%s\n", server->last_request_id, request);
    if (vstream_fflush(server->impl->sasl_stream) == VSTREAM_EOF) {
	vstring_strcpy(reply, "Connection lost to authentication server");
	xsasl_internal_server_disconnect(server->impl);
	return XSASL_AUTH_TEMP;
    }
    return xsasl_internal_handle_reply(server, reply);
}

static const char *xsasl_internal_server_get_username(XSASL_SERVER *xp)
{
    XSASL_INTERNAL_SERVER *server = (XSASL_INTERNAL_SERVER *) xp;

    return (server->username);
}

#endif
