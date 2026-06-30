#include <sys_defs.h>
#include <string.h>
#include <stdio.h>

#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <ldap.h>

#include <msg.h>
#include <mymalloc.h>
#include <vstring.h>
#include <stringops.h>
#include <cryptmaps.h>

#include "auth.h"

static const char *auth_ldap_entry_label(const AUTH_LDAP_ENTRY *entry,
					          VSTRING *buf)
{
    vstring_sprintf(buf, "id=%ld priority=%d uri=%s://%s:%d",
		    (long) entry->id, entry->priority,
		    entry->ldap ? entry->ldap : "ldap",
		    entry->server ? entry->server : "",
		    entry->port > 0 ? entry->port : 389);
    return (vstring_str(buf));
}

static char *auth_ldap_build_filter(const AUTH_LDAP_ENTRY *entry,
				            const char *login)
{
    const char *sf = entry->search_filter;
    const char *login_attr = entry->login_attribute;

    if (sf == 0 || *sf == 0 || login_attr == 0 || *login_attr == 0)
	return (0);
    if (sf[0] == '&')
	return (concatenate("(&", sf + 1, "(", login_attr, "=", login, "))", (char *) 0));
    return (concatenate("(&(", sf, ")(", login_attr, "=", login, "))", (char *) 0));
}

static int auth_ldap_scope(const char *scope)
{
    if (scope == 0 || *scope == 0 || strcasecmp(scope, "subtree") == 0)
	return LDAP_SCOPE_SUBTREE;
    if (strcasecmp(scope, "base") == 0)
	return LDAP_SCOPE_BASE;
    if (strcasecmp(scope, "onelevel") == 0)
	return LDAP_SCOPE_ONELEVEL;
    return LDAP_SCOPE_SUBTREE;
}

static int auth_ldap_try_entry(const AUTH_LDAP_ENTRY *entry,
			               const char *login, const char *plain,
			               char **used_entry)
{
    const char *myname = "auth_ldap_try_entry";
    LDAP   *ld = 0;
    VSTRING *uri = vstring_alloc(64);
    VSTRING *label = vstring_alloc(64);
    char   *entry_label_copy;
    int     version;
    int     rc;
    char   *filter;
    const char *bind_pwd;
    LDAPMessage *res = 0;
    LDAPMessage *entry_msg;
    char   *user_dn;
    struct berval cred;
    char   *attrs[] = {(char *) "dn", 0};

    entry_label_copy = mystrdup(auth_ldap_entry_label(entry, label));

    vstring_sprintf(uri, "%s://%s:%d",
		    entry->ldap ? entry->ldap : "ldap",
		    entry->server ? entry->server : "",
		    entry->port > 0 ? entry->port : 389);

    if (ldap_initialize(&ld, vstring_str(uri)) != LDAP_SUCCESS) {
	msg_warn("%s: %s: ldap_initialize failed", myname, entry_label_copy);
	myfree(entry_label_copy);
	vstring_free(uri);
	vstring_free(label);
	return (0);
    }

    version = entry->ldap_protocol_version > 0 ? entry->ldap_protocol_version : 3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    if (entry->start_tls) {
	rc = ldap_start_tls_s(ld, 0, 0);
	if (rc != LDAP_SUCCESS) {
	    msg_warn("%s: %s: ldap_start_tls failed: %s", myname, entry_label_copy,
		     ldap_err2string(rc));
	    ldap_unbind_ext_s(ld, 0, 0);
	    myfree(entry_label_copy);
	    vstring_free(uri);
	    vstring_free(label);
	    return (0);
	}
    }

    bind_pwd = cryptmaps_expand(entry->auth_bind_user_pwd ?
				entry->auth_bind_user_pwd : "");

    if (entry->auth_bind) {
	rc = ldap_simple_bind_s(ld, entry->auth_bind_user_dn, bind_pwd);
	if (rc != LDAP_SUCCESS) {
	    msg_warn("%s: %s: service bind failed: %s", myname, entry_label_copy,
		     ldap_err2string(rc));
	    ldap_unbind_ext_s(ld, 0, 0);
	    myfree(entry_label_copy);
	    vstring_free(uri);
	    vstring_free(label);
	    return (0);
	}
    } else {
	rc = ldap_simple_bind_s(ld, 0, 0);
	if (rc != LDAP_SUCCESS) {
	    msg_warn("%s: %s: anonymous bind failed: %s", myname, entry_label_copy,
		     ldap_err2string(rc));
	    ldap_unbind_ext_s(ld, 0, 0);
	    myfree(entry_label_copy);
	    vstring_free(uri);
	    vstring_free(label);
	    return (0);
	}
    }

    filter = auth_ldap_build_filter(entry, login);
    if (filter == 0) {
	msg_warn("%s: %s: malformed search filter", myname, entry_label_copy);
	ldap_unbind_ext_s(ld, 0, 0);
	myfree(entry_label_copy);
	vstring_free(uri);
	vstring_free(label);
	return (0);
    }

    rc = ldap_search_ext_s(ld, entry->base_dn, auth_ldap_scope(entry->scope),
			   filter, attrs, 0, 0, 0, 0, 0, &res);
    if (rc != LDAP_SUCCESS || res == 0) {
	msg_info("%s: %s: search failed base=%s filter=%s: %s", myname,
		 entry_label_copy, entry->base_dn ? entry->base_dn : "",
		 filter, ldap_err2string(rc));
	myfree(filter);
	if (res)
	    ldap_msgfree(res);
	ldap_unbind_ext_s(ld, 0, 0);
	myfree(entry_label_copy);
	vstring_free(uri);
	vstring_free(label);
	return (0);
    }
    myfree(filter);

    entry_msg = ldap_first_entry(ld, res);
    if (entry_msg == 0) {
	msg_info("%s: %s: user not found base=%s login=%s", myname,
		 entry_label_copy, entry->base_dn ? entry->base_dn : "", login);
	ldap_msgfree(res);
	ldap_unbind_ext_s(ld, 0, 0);
	myfree(entry_label_copy);
	vstring_free(uri);
	vstring_free(label);
	return (0);
    }

    user_dn = ldap_get_dn(ld, entry_msg);
    ldap_msgfree(res);
    if (user_dn == 0) {
	ldap_unbind_ext_s(ld, 0, 0);
	myfree(entry_label_copy);
	vstring_free(uri);
	vstring_free(label);
	return (0);
    }

    cred.bv_len = strlen(plain);
    cred.bv_val = (char *) plain;
    rc = ldap_sasl_bind_s(ld, user_dn, LDAP_SASL_SIMPLE, &cred, 0, 0, 0);
    ldap_memfree(user_dn);
    ldap_unbind_ext_s(ld, 0, 0);
    vstring_free(uri);
    vstring_free(label);

    if (rc != LDAP_SUCCESS) {
	msg_info("%s: %s: user bind failed login=%s: %s", myname, entry_label_copy,
		 login, ldap_err2string(rc));
	myfree(entry_label_copy);
	return (0);
    }
    if (used_entry != 0)
	*used_entry = entry_label_copy;
    else
	myfree(entry_label_copy);
    return (1);
}

int     auth_ldap_authenticate(const char *login, const char *plain,
			               char **used_entry)
{
    const AUTH_LDAP_ENTRY *entries;
    size_t  count;
    size_t  i;

    if (used_entry != 0)
	*used_entry = 0;
    entries = auth_ldap_chain_snapshot(&count);
    if (entries == 0 || count == 0)
	return (0);

    for (i = 0; i < count; i++) {
	if (auth_ldap_try_entry(entries + i, login, plain, used_entry))
	    return (1);
    }
    return (0);
}
