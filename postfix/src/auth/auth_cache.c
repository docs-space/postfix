#include <sys_defs.h>
#include <string.h>
#include <time.h>

#include <msg.h>
#include <mymalloc.h>
#include <htable.h>
#include <vstring.h>

#include "auth.h"

extern int var_auth_cred_cache_ttl;

typedef struct {
    time_t  expire;
    int     success;
} AUTH_CACHE_ENTRY;

static HTABLE *auth_cred_cache;

static char *auth_cred_cache_key(const char *login, const char *node)
{
    VSTRING *key = vstring_alloc(64);

    vstring_sprintf(key, "%s\t%s", login, node ? node : "");
    return (vstring_export(key));
}

void    auth_cred_cache_flush(void)
{
    if (auth_cred_cache) {
	htable_free(auth_cred_cache, (void (*) (void *)) 0);
	auth_cred_cache = 0;
    }
}

int     auth_cred_cache_lookup(const char *login, const char *node, int *success)
{
    AUTH_CACHE_ENTRY *entry;
    char   *key;
    time_t  now;

    if (var_auth_cred_cache_ttl <= 0)
	return (0);
    if (auth_cred_cache == 0)
	return (0);
    key = auth_cred_cache_key(login, node);
    entry = (AUTH_CACHE_ENTRY *) htable_find(auth_cred_cache, key);
    myfree(key);
    if (entry == 0)
	return (0);
    now = time((time_t *) 0);
    if (entry->expire < now)
	return (0);
    *success = entry->success;
    return (1);
}

void    auth_cred_cache_store(const char *login, const char *node, int success)
{
    AUTH_CACHE_ENTRY *entry;
    char   *key;
    time_t  now;

    if (var_auth_cred_cache_ttl <= 0)
	return;
    if (auth_cred_cache == 0)
	auth_cred_cache = htable_create(10);
    key = auth_cred_cache_key(login, node);
    entry = (AUTH_CACHE_ENTRY *) htable_find(auth_cred_cache, key);
    if (entry == 0) {
	entry = (AUTH_CACHE_ENTRY *) mymalloc(sizeof(*entry));
	htable_enter(auth_cred_cache, key, (void *) entry);
    } else {
	myfree(key);
    }
    now = time((time_t *) 0);
    entry->expire = now + var_auth_cred_cache_ttl;
    entry->success = success;
}
