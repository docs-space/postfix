#include <sys_defs.h>
#include <string.h>

#include <msg.h>
#include <mymalloc.h>
#include <maps.h>

#include "auth.h"

extern char *var_auth_authenticate_maps;

#define AUTH_PG_FIELD_SEP	'\x1f'

static MAPS *auth_authenticate_maps;

int     auth_pg_init(void)
{
    if (*var_auth_authenticate_maps == 0) {
	msg_warn("auth: auth_authenticate_maps is not configured");
	return (-1);
    }
    if (auth_authenticate_maps != 0)
	return (0);
    auth_authenticate_maps = maps_create("auth authenticate",
					var_auth_authenticate_maps,
					DICT_FLAG_LOCK | DICT_FLAG_FOLD_FIX);
    return (auth_authenticate_maps != 0 ? 0 : -1);
}

void    auth_pg_shutdown(void)
{
    if (auth_authenticate_maps) {
	maps_free(auth_authenticate_maps);
	auth_authenticate_maps = 0;
    }
}

int     auth_pg_lookup(const char *login, const char *unused_node,
			          AUTH_PG_RESULT *result)
{
    const char *value;
    char   *copy;
    char   *allow_nets;

    (void) unused_node;

    memset((void *) result, 0, sizeof(*result));
    if (auth_authenticate_maps == 0 && auth_pg_init() < 0)
	return (-1);
    if ((value = maps_find(auth_authenticate_maps, login, 0)) == 0)
	return (0);

    copy = mystrdup(value);
    allow_nets = strchr(copy, AUTH_PG_FIELD_SEP);
    if (allow_nets != 0) {
	*allow_nets++ = 0;
	if (*allow_nets != 0)
	    result->allow_nets = mystrdup(allow_nets);
    }
    if (*copy != 0)
	result->password = mystrdup(copy);
    myfree(copy);
    return (result->password != 0 ? 1 : 0);
}

void    auth_pg_result_free(AUTH_PG_RESULT *result)
{
    if (result->password) {
	myfree(result->password);
	result->password = 0;
    }
    if (result->allow_nets) {
	myfree(result->allow_nets);
	result->allow_nets = 0;
    }
}
