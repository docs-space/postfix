#include <sys_defs.h>
#include <string.h>
#include <stdio.h>

#include <msg.h>
#include <mymalloc.h>
#include <vstream.h>
#include <vstring.h>
#include <cidr_match.h>
#include <split_at.h>

#include "auth.h"

int     auth_nets_permit(const char *allow_nets, const char *rip)
{
    char   *copy;
    char   *tok;
    char   *next;

    if (allow_nets == 0 || *allow_nets == 0)
	return (1);
    if (rip == 0 || *rip == 0)
	return (0);

    copy = mystrdup(allow_nets);
    for (tok = copy; tok != 0; tok = next) {
	CIDR_MATCH info;
	VSTRING *why = vstring_alloc(1);
	int     match;

	next = split_at(tok, ',');
	while (*tok == ' ' || *tok == '\t')
	    tok++;
	if (*tok == 0)
	    continue;
	if (cidr_match_parse(&info, tok, CIDR_MATCH_TRUE, why) != 0) {
	    vstring_free(why);
	    continue;
	}
	match = (cidr_match_execute(&info, rip) != 0);
	vstring_free(why);
	if (match) {
	    myfree(copy);
	    return (1);
	}
    }
    myfree(copy);
    return (0);
}
