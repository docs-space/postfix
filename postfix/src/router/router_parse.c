/*++
/* NAME
/*	router_parse 3
/* SUMMARY
/*	parse transport route body for router delivery
/* LICENSE
/*	The Secure Mailer license must be distributed with this software.
/*--*/

/* System library. */

#include <sys_defs.h>
#include <string.h>
#include <ctype.h>

/* Utility library. */

#include <mymalloc.h>
#include <split_at.h>
#include <msg.h>

/* Application-specific. */

#include "router.h"

static const char *router_smtp_transports[] = {
    "lmtp", "lmtps", "smtp", "smtp-tls", "smtps", "relay", 0,
};

/* router_is_smtp_family - allowed backend transport name */

static int router_is_smtp_family(const char *transport)
{
    const char **cpp;

    if (transport == 0 || *transport == 0)
	return (0);
    for (cpp = router_smtp_transports; *cpp; cpp++)
	if (strcmp(transport, *cpp) == 0)
	    return (1);
    return (0);
}

/* router_route_free - destroy parse result */

void    router_route_free(ROUTER_ROUTE *route)
{
    int     i;

    if (route == 0)
	return;
    for (i = 0; i < route->count; i++) {
	myfree(route->groups[i].transport);
	myfree(route->groups[i].nexthop);
    }
    myfree((char *) route->groups);
    myfree((char *) route);
}

/* router_parse - split route body on ';' into transport groups */

ROUTER_ROUTE *router_parse(const char *body)
{
    const char *myname = "router_parse";
    ROUTER_ROUTE *route;
    char   *saved;
    char   *seg;
    char   *next;
    char   *transport;
    char   *nexthop;
    int     nseg;
    int     i;

    if (body == 0 || *body == 0) {
	msg_warn("%s: empty route body", myname);
	return (0);
    }

    /*
     * Count segments.
     */
    saved = mystrdup(body);
    nseg = 0;
    for (seg = saved; seg != 0; seg = next) {
	next = split_at(seg, ';');
	if (*seg != 0)
	    nseg++;
    }
    myfree(saved);
    if (nseg == 0) {
	msg_warn("%s: empty route body", myname);
	return (0);
    }

    route = (ROUTER_ROUTE *) mymalloc(sizeof(*route));
    route->groups = (ROUTER_GROUP *) mymalloc(nseg * sizeof(*route->groups));
    route->count = 0;

    saved = mystrdup(body);
    for (seg = saved; seg != 0; seg = next) {
	next = split_at(seg, ';');
	if (*seg == 0)
	    continue;
	transport = seg;
	nexthop = split_at(seg, ':');
	if (nexthop == 0 || *transport == 0) {
	    msg_warn("%s: bad route segment \"%s\"", myname, seg);
	    router_route_free(route);
	    myfree(saved);
	    return (0);
	}
	if (!router_is_smtp_family(transport)) {
	    msg_warn("%s: unsupported transport \"%s\" in route", myname, transport);
	    router_route_free(route);
	    myfree(saved);
	    return (0);
	}
	i = route->count++;
	route->groups[i].transport = mystrdup(transport);
	route->groups[i].nexthop = mystrdup(nexthop ? nexthop : "");
    }
    myfree(saved);
    return (route);
}

#ifdef TEST

#include <stdlib.h>
#include <string.h>
#include <vstream.h>
#include <vstring_vstream.h>

static NORETURN usage(const char *progname)
{
    msg_fatal("usage: %s route-body", progname);
}

static void print_route(ROUTER_ROUTE *route)
{
    int     i;

    if (route == 0) {
	vstream_printf("parse failed\n");
	return;
    }
    for (i = 0; i < route->count; i++)
	vstream_printf("%d: transport=%s nexthop=%s\n",
		       i, route->groups[i].transport, route->groups[i].nexthop);
    router_route_free(route);
}

int     main(int argc, char **argv)
{
    VSTRING *buf = vstring_alloc(100);
    ROUTER_ROUTE *route;

    if (argc != 2)
	usage(argv[0]);
    route = router_parse(argv[1]);
    print_route(route);
    route = router_parse("lmtp:[2001:db8::1]:24;smtp:host1,host2");
    print_route(route);
    route = router_parse("pipe:/bin/true");
    print_route(route);
    vstring_free(buf);
    return (0);
}

#endif
