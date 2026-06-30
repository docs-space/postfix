#include <sys_defs.h>
#include <string.h>

#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <msg.h>
#include <mymalloc.h>
#include <cryptmaps.h>

#include "../postapi/auth_key.h"
#include "auth.h"

static int auth_str_equal(const char *a, const char *b)
{
    size_t  alen;
    size_t  blen;

    if (a == 0 || b == 0)
	return (0);
    alen = strlen(a);
    blen = strlen(b);
    if (alen != blen)
	return (0);
    return (memcmp(a, b, alen) == 0);
}

static char *auth_strip_aes_suffix(char *stored)
{
    char   *suffix;

    suffix = strrchr(stored, '$');
    if (suffix != 0 && suffix > stored && strchr(suffix, '{') == 0)
	*suffix = 0;
    return (stored);
}

int     auth_verify_password(const char *stored, const char *plain)
{
    char   *copy;
    const char *expanded;
    int     result;

    if (stored == 0 || *stored == 0 || plain == 0)
	return (0);

    copy = mystrdup(stored);
    auth_strip_aes_suffix(copy);

    if (strncasecmp(copy, "{SHA1.HEX}", 10) == 0) {
	result = (auth_key_validate(copy, plain) == AUTH_KEY_OK);
	myfree(copy);
	return (result);
    }

    expanded = cryptmaps_expand(copy);
    if (expanded == 0) {
	myfree(copy);
	return (0);
    }
    if (expanded != copy && *expanded != '{') {
	result = auth_str_equal(expanded, plain);
	myfree(copy);
	return (result);
    }

    result = (auth_key_validate(copy, plain) == AUTH_KEY_OK);
    myfree(copy);
    return (result);
}
