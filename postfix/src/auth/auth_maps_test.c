#include <sys_defs.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <msg.h>
#include <mymalloc.h>
#include <vstring.h>

#include "auth.h"

extern char *var_auth_ldap_chain_maps;

static int test_blob_split(void)
{
    const char *blob = "1\x1f" "10\x1f" "ldap\x1f" "ldap.example\x1f" "389\x1f"
	"false\x1f" "true\x1f" "cn=bind\x1f" "pwd\x1f" "dc=example,dc=com\x1f"
	"(objectClass=person)\x1f" "uid\x1f" "subtree\x1f" "mail\x1f"
	"never\x1f" "*\x1f" "PLAIN\x1f" "3";
    AUTH_LDAP_ENTRY *entries;
    size_t  count = 0;
    int     ok = 1;

    var_auth_ldap_chain_maps = "";
    entries = 0;
    {
	char   *copy = mystrdup(blob);
	char   *rec;
	char   *next_rec;
	size_t  n = 0;
	size_t  alloc = 2;

	entries = (AUTH_LDAP_ENTRY *) mymalloc(alloc * sizeof(*entries));
	for (rec = copy; rec != 0; rec = next_rec) {
	    char   *fld;
	    char   *next_fld;
	    char  **fields;
	    size_t  nfields = 0;
	    AUTH_LDAP_ENTRY *parsed;

	    next_rec = strchr(rec, '\x1e');
	    if (next_rec)
		*next_rec++ = 0;
	    fields = (char **) mymalloc(AUTH_LDAP_FIELD_COUNT * sizeof(*fields));
	    for (fld = rec; fld != 0; fld = next_fld) {
		next_fld = strchr(fld, '\x1f');
		if (next_fld)
		    *next_fld++ = 0;
		fields[nfields++] = fld;
	    }
	    parsed = (AUTH_LDAP_ENTRY *) mymalloc(sizeof(*parsed));
	    memset(parsed, 0, sizeof(*parsed));
	    if (nfields >= AUTH_LDAP_FIELD_COUNT) {
		parsed->id = atol(fields[0]);
		parsed->priority = atoi(fields[1]);
		parsed->server = mystrdup(fields[3]);
	    }
	    if (n >= alloc) {
		alloc *= 2;
		entries = (AUTH_LDAP_ENTRY *) myrealloc((void *) entries,
							alloc * sizeof(*entries));
	    }
	    entries[n++] = *parsed;
	    myfree(parsed);
	    myfree(fields);
	}
	myfree(copy);
	count = n;
    }

    if (count != 1 || entries[0].id != 1 || entries[0].priority != 10
	|| strcmp(entries[0].server, "ldap.example") != 0)
	ok = 0;
    auth_ldap_chain_free(entries, count);
    return (ok);
}

int     main(void)
{
    int     fail = 0;

    if (!test_blob_split()) {
	fprintf(stderr, "auth_maps_test: blob split failed\n");
	fail = 1;
    }
    return (fail ? 1 : 0);
}
