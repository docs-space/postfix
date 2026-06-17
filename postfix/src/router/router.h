#ifndef _ROUTER_H_INCLUDED_
#define _ROUTER_H_INCLUDED_

#include <vstream.h>

typedef struct ROUTER_GROUP {
    char   *transport;
    char   *nexthop;
} ROUTER_GROUP;

typedef struct ROUTER_ROUTE {
    ROUTER_GROUP *groups;
    int     count;
} ROUTER_ROUTE;

extern ROUTER_ROUTE *router_parse(const char *body);
extern void router_route_free(ROUTER_ROUTE *);
extern void router_service(VSTREAM *, char *, char **);

#endif
