/*++
/* NAME
/*	router 8
/* SUMMARY
/*	Postfix multi-transport delivery router
/* LICENSE
/*	The Secure Mailer license must be distributed with this software.
/*--*/

/* System library. */

#include <sys_defs.h>

/* Global library. */

#include <mail_server.h>
#include <mail_version.h>

/* Application-specific. */

#include "router.h"

MAIL_VERSION_STAMP_DECLARE;

/* main - pass control to the single-threaded skeleton */

int     main(int argc, char **argv)
{

    MAIL_VERSION_STAMP_ALLOCATE;

    single_server_main(argc, argv, router_service, 0);
}
