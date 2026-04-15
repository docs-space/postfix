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

#include <mail_version.h>
#include <mail_server.h>
#include <msg.h>
#include <vstream.h>
#include <vstring.h>

static void postapi_service(VSTREAM *client_stream, char *service, char **argv)
{
    VSTRING *request_line = vstring_alloc(256);

    (void) service;
    (void) argv;

    if (vstring_get_nonl(request_line, client_stream) != VSTREAM_EOF)
	msg_info("postapi request: %s", vstring_str(request_line));

    vstream_fprintf(client_stream,
		    "HTTP/1.1 200 OK\r\n"
		    "Content-Type: application/json\r\n"
		    "Connection: close\r\n"
		    "\r\n"
		    "{\"service\":\"postapi\",\"status\":\"ok\"}\n");
    vstream_fflush(client_stream);
    vstring_free(request_line);
}

MAIL_VERSION_STAMP_DECLARE;

int     main(int argc, char **argv)
{
    MAIL_VERSION_STAMP_ALLOCATE;

    single_server_main(argc, argv, postapi_service, 0);
}
