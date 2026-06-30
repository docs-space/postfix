#include <sys_defs.h>
#include <string.h>
#include <stdlib.h>

#include <msg.h>
#include <mymalloc.h>
#include <maps.h>
#include <mail_params.h>
#include <split_at.h>

#include "auth.h"

extern char *var_auth_ldap_chain_maps;

#define AUTH_LDAP_CHAIN_KEY	"chain"
#define AUTH_LDAP_REC_SEP	'\x1e'
#define AUTH_LDAP_FLD_SEP	'\x1f'

static MAPS *auth_ldap_chain_maps;
static AUTH_LDAP_ENTRY *auth_ldap_snapshot;
static size_t auth_ldap_snapshot_count;

static void auth_ldap_entry_free(AUTH_LDAP_ENTRY *entry)
{
    if (entry == 0)
	return;
    myfree(entry->ldap);
    myfree(entry->server);
    myfree(entry->auth_bind_user_dn);
    myfree(entry->auth_bind_user_pwd);
    myfree(entry->base_dn);
    myfree(entry->search_filter);
    myfree(entry->login_attribute);
    myfree(entry->scope);
    myfree(entry->email_attribute);
    myfree(entry->referral_following);
    myfree(entry->user_login_mask);
    myfree(entry->default_pass_scheme);
    myfree(entry);
}

void    auth_ldap_chain_free(AUTH_LDAP_ENTRY *entries, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++)
	auth_ldap_entry_free(entries + i);
    myfree(entries);
}

static AUTH_LDAP_ENTRY *auth_ldap_parse_fields(char **fields, size_t nfields)
{
    AUTH_LDAP_ENTRY *entry;

    if (nfields < AUTH_LDAP_FIELD_COUNT)
	return (0);
    entry = (AUTH_LDAP_ENTRY *) mymalloc(sizeof(*entry));
    memset((void *) entry, 0, sizeof(*entry));
    entry->id = atol(fields[0]);
    entry->priority = atoi(fields[1]);
    entry->ldap = mystrdup(fields[2]);
    entry->server = mystrdup(fields[3]);
    entry->port = atoi(fields[4]);
    entry->start_tls = (strcmp(fields[5], "t") == 0
			|| strcmp(fields[5], "true") == 0
			|| strcmp(fields[5], "1") == 0);
    entry->auth_bind = (strcmp(fields[6], "t") == 0
			|| strcmp(fields[6], "true") == 0
			|| strcmp(fields[6], "1") == 0);
    entry->auth_bind_user_dn = mystrdup(fields[7]);
    entry->auth_bind_user_pwd = mystrdup(fields[8]);
    entry->base_dn = mystrdup(fields[9]);
    entry->search_filter = mystrdup(fields[10]);
    entry->login_attribute = mystrdup(fields[11]);
    entry->scope = mystrdup(fields[12]);
    entry->email_attribute = mystrdup(fields[13]);
    entry->referral_following = mystrdup(fields[14]);
    entry->user_login_mask = mystrdup(fields[15]);
    entry->default_pass_scheme = mystrdup(fields[16]);
    entry->ldap_protocol_version = atoi(fields[17]);
    if (entry->ldap_protocol_version <= 0)
	entry->ldap_protocol_version = 3;
    return (entry);
}

static AUTH_LDAP_ENTRY *auth_ldap_parse_blob(const char *blob, size_t *count)
{
    const char *myname = "auth_ldap_parse_blob";
    char   *copy;
    char   *rec;
    char   *next_rec;
    AUTH_LDAP_ENTRY *entries;
    size_t  alloc = 4;
    size_t  n = 0;

    *count = 0;
    if (blob == 0 || *blob == 0)
	return (0);

    copy = mystrdup(blob);
    entries = (AUTH_LDAP_ENTRY *) mymalloc(alloc * sizeof(*entries));

    for (rec = copy; rec != 0; rec = next_rec) {
	char   *fld;
	char   *next_fld;
	char  **fields;
	size_t  nfields = 0;
	size_t  fcap = AUTH_LDAP_FIELD_COUNT + 2;
	AUTH_LDAP_ENTRY *parsed;

	next_rec = strchr(rec, AUTH_LDAP_REC_SEP);
	if (next_rec)
	    *next_rec++ = 0;
	if (*rec == 0)
	    continue;

	fields = (char **) mymalloc(fcap * sizeof(*fields));
	for (fld = rec; fld != 0; fld = next_fld) {
	    next_fld = strchr(fld, AUTH_LDAP_FLD_SEP);
	    if (next_fld)
		*next_fld++ = 0;
	    if (nfields >= fcap) {
		fcap *= 2;
		fields = (char **) myrealloc((void *) fields,
					     fcap * sizeof(*fields));
	    }
	    fields[nfields++] = fld;
	}
	parsed = auth_ldap_parse_fields(fields, nfields);
	myfree(fields);
	if (parsed == 0) {
	    msg_warn("%s: malformed LDAP chain entry", myname);
	    continue;
	}
	if (n >= alloc) {
	    alloc *= 2;
	    entries = (AUTH_LDAP_ENTRY *) myrealloc((void *) entries,
						    alloc * sizeof(*entries));
	}
	entries[n++] = *parsed;
	myfree(parsed);
    }
    myfree(copy);
    *count = n;
    return (entries);
}

int     auth_maps_load_ldap_chain(void)
{
    const char *myname = "auth_maps_load_ldap_chain";
    const char *blob;
    AUTH_LDAP_ENTRY *entries;
    size_t  count = 0;

    if (auth_ldap_chain_maps == 0) {
	if (*var_auth_ldap_chain_maps == 0)
	    return (0);
	auth_ldap_chain_maps = maps_create("auth ldap chain",
					  var_auth_ldap_chain_maps,
					  DICT_FLAG_LOCK | DICT_FLAG_FOLD_FIX);
    }
    if ((blob = maps_find(auth_ldap_chain_maps, AUTH_LDAP_CHAIN_KEY, 0)) == 0)
	blob = "";
    entries = auth_ldap_parse_blob(blob, &count);
    auth_ldap_chain_free(auth_ldap_snapshot, auth_ldap_snapshot_count);
    auth_ldap_snapshot = entries;
    auth_ldap_snapshot_count = count;
    if (msg_verbose)
	msg_info("%s: loaded %lu LDAP chain entries", myname, (unsigned long) count);
    return (0);
}

int     auth_ldap_chain_reload(void)
{
    return (auth_maps_load_ldap_chain());
}

const AUTH_LDAP_ENTRY *auth_ldap_chain_snapshot(size_t *count)
{
    if (count)
	*count = auth_ldap_snapshot_count;
    return (auth_ldap_snapshot);
}
