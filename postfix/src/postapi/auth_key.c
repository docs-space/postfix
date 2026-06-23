/*++
/* NAME
/*	auth_key 3
/* SUMMARY
/*	postapi access token validation
/* SYNOPSIS
/*	#include "auth_key.h"
/*
/*	int	auth_key_validate(map_value, bearer_token)
/*	const char *map_value;
/*	const char *bearer_token;
/*--*/

#include <sys_defs.h>
#include <string.h>
#include <ctype.h>

#ifdef STRCASECMP_IN_STRINGS_H
#include <strings.h>
#endif

#include <msg.h>
#include <mymalloc.h>
#include <vstring.h>
#include <hex_code.h>

#include "auth_key.h"

#ifdef USE_TLS
#include <ossl_digest.h>
#endif

#define AUTH_KEY_SHA1_SCHEME		"SHA1.HEX"

#define STR(x)	vstring_str(x)
#define LEN(x)	VSTRING_LEN(x)

 /* auth_key_delim - credential separator */

static int auth_key_delim(int ch)
{
    return (ch == 0 || ch == ',' || ch == '\n' || ch == '\r' || ch == '\t'
	    || ch == ' ');
}

 /* auth_key_str_equal - constant-time-ish string compare */

static int auth_key_str_equal(const char *a, const char *b)
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

 /* auth_key_hex_equal - case-insensitive hex compare */

static int auth_key_hex_equal(const char *a, const char *b)
{
    if (a == 0 || b == 0)
	return (0);
    while (*a && *b) {
	if (tolower((unsigned char) *a) != tolower((unsigned char) *b))
	    return (0);
	a++;
	b++;
    }
    return (*a == 0 && *b == 0);
}

#ifdef USE_TLS

 /* auth_key_sha1_hex - UTF-8 SHA1 as upper-case hex (mail.admin.api) */

static int auth_key_sha1_hex(const char *plain, VSTRING *hex_out)
{
    OSSL_DGST *dgst;
    VSTRING *raw = vstring_alloc(32);

    if ((dgst = ossl_digest_new("sha1")) == 0) {
	vstring_free(raw);
	return (-1);
    }
    if (ossl_digest_data(dgst, plain, (ssize_t) strlen(plain), raw) != 0) {
	ossl_digest_free(dgst);
	vstring_free(raw);
	return (-1);
    }
    ossl_digest_free(dgst);
    hex_encode(hex_out, STR(raw), LEN(raw));
    return (0);
}

 /* auth_key_check_sha1_hex - {SHA1.HEX} */

static int auth_key_check_sha1_hex(const char *expected_hex, const char *bearer)
{
    VSTRING *hex = vstring_alloc(64);

    if (auth_key_sha1_hex(bearer, hex) != 0) {
	vstring_free(hex);
	return (0);
    }
    if (!auth_key_hex_equal(STR(hex), expected_hex)) {
	vstring_free(hex);
	return (0);
    }
    vstring_free(hex);
    return (1);
}

#endif

 /* auth_key_validate - compare bearer against expanded map segments */

int     auth_key_validate(const char *map_value, const char *bearer_token)
{
    const char *cp;
    int     saw_entry = 0;

    if (map_value == 0 || *map_value == 0 || bearer_token == 0)
	return (AUTH_KEY_FORMAT_ERR);

    cp = map_value;
    for (;;) {
	while (auth_key_delim(*cp))
	    cp++;
	if (*cp == 0)
	    break;
	if (*cp == '{') {
	    const char *scheme = cp + 1;
	    const char *payload;
	    const char *payload_end;
	    ssize_t scheme_len;
	    ssize_t payload_len;
	    char   *scheme_buf;
	    char   *payload_buf;
	    int     match = 0;

	    cp++;
	    while (*cp && *cp != '}')
		cp++;
	    if (*cp != '}' || scheme == cp) {
		msg_warn("postapi: malformed access token map value");
		return (AUTH_KEY_FORMAT_ERR);
	    }
	    scheme_len = (cp - 1) - scheme;
	    cp++;
	    payload = cp;
	    payload_end = cp;
	    while (*payload_end && *payload_end != '{'
		   && !auth_key_delim(*payload_end))
		payload_end++;
	    if (payload_end <= payload) {
		msg_warn("postapi: malformed access token map value");
		return (AUTH_KEY_FORMAT_ERR);
	    }
	    payload_len = payload_end - payload;
	    scheme_buf = mystrndup(scheme, scheme_len);
	    payload_buf = mystrndup(payload, payload_len);
	    saw_entry = 1;
#ifdef USE_TLS
	    if (strcasecmp(scheme_buf, AUTH_KEY_SHA1_SCHEME) == 0)
		match = auth_key_check_sha1_hex(payload_buf, bearer_token);
	    else
		msg_warn("postapi: unknown auth key scheme \"%s\"", scheme_buf);
#else
	    msg_warn("postapi: auth key scheme \"%s\" requires TLS/OpenSSL build",
		     scheme_buf);
#endif
	    myfree(scheme_buf);
	    myfree(payload_buf);
	    if (match)
		return (AUTH_KEY_OK);
	    cp = payload_end;
	} else {
	    const char *plain = cp;
	    const char *plain_end = cp;

	    while (*plain_end && *plain_end != '{'
		   && !auth_key_delim(*plain_end))
		plain_end++;
	    if (plain_end > plain) {
		char   *plain_buf;

		saw_entry = 1;
		plain_buf = mystrndup(plain, plain_end - plain);
		if (auth_key_str_equal(plain_buf, bearer_token)) {
		    myfree(plain_buf);
		    return (AUTH_KEY_OK);
		}
		myfree(plain_buf);
	    }
	    cp = plain_end;
	}
    }
    if (!saw_entry)
	return (AUTH_KEY_FORMAT_ERR);
    return (AUTH_KEY_MISMATCH);
}
