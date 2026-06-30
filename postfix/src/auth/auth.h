#ifndef AUTH_H_INCLUDED_
#define AUTH_H_INCLUDED_

#include <stddef.h>

#define AUTH_LDAP_FIELD_COUNT	18

typedef struct AUTH_LDAP_ENTRY {
    long    id;
    int     priority;
    char   *ldap;
    char   *server;
    int     port;
    int     start_tls;
    int     auth_bind;
    char   *auth_bind_user_dn;
    char   *auth_bind_user_pwd;
    char   *base_dn;
    char   *search_filter;
    char   *login_attribute;
    char   *scope;
    char   *email_attribute;
    char   *referral_following;
    char   *user_login_mask;
    char   *default_pass_scheme;
    int     ldap_protocol_version;
} AUTH_LDAP_ENTRY;

typedef struct AUTH_PG_RESULT {
    char   *password;
    char   *allow_nets;
} AUTH_PG_RESULT;

extern void auth_ldap_chain_free(AUTH_LDAP_ENTRY *, size_t);
extern int auth_ldap_chain_reload(void);
extern const AUTH_LDAP_ENTRY *auth_ldap_chain_snapshot(size_t *);

extern int auth_maps_load_ldap_chain(void);

extern int auth_pg_init(void);
extern void auth_pg_shutdown(void);
extern int auth_pg_lookup(const char *login, const char *node,
			          AUTH_PG_RESULT *);

extern void auth_pg_result_free(AUTH_PG_RESULT *);
extern int auth_verify_password(const char *stored, const char *plain);
extern int auth_nets_permit(const char *allow_nets, const char *rip);

extern int auth_cred_cache_lookup(const char *login, const char *node,
				          int *success);
extern void auth_cred_cache_store(const char *login, const char *node,
				          int success);
extern void auth_cred_cache_flush(void);

extern int auth_ldap_authenticate(const char *login, const char *plain);

#endif
