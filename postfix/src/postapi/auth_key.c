/*++
/* NAME
/*	auth_key 3
/* SUMMARY
/*	postapi access token validation
/* SYNOPSIS
/*	#include "auth_key.h"
/*
/*	int	auth_key_validate(map_value, bearer_token, salt_maps)
/*	const char *map_value;
/*	const char *bearer_token;
/*	MAPS *salt_maps;
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
#include <base64_code.h>
#include <maps.h>

#include "auth_key.h"

#ifdef USE_TLS
#include <openssl/evp.h>
#include <openssl/err.h>
#include <ossl_digest.h>
#endif

#define AUTH_KEY_AES_SCHEME		"AES-256-CBC"
#define AUTH_KEY_SHA1_SCHEME		"SHA1.HEX"
#define AUTH_KEY_PLAIN_SCHEME		"PLAIN"
#define AUTH_KEY_DERIV_ITERATIONS	1000
#define AUTH_KEY_SALT_IV_BYTES		16

#define STR(x)	vstring_str(x)
#define LEN(x)	VSTRING_LEN(x)

 /* auth_key_delim - credential separator */

static int auth_key_delim(int ch)
{
    return (ch == 0 || ch == ',' || ch == '\n' || ch == '\r' || ch == '\t'
	    || ch == ' ');
}

 /* auth_key_trim_trailing_space - match C# DecryptWithTrim */

static void auth_key_trim_trailing_space(VSTRING *vp)
{
    ssize_t len = LEN(vp);

    while (len > 0 && ((unsigned char) STR(vp)[len - 1]) <= ' ')
	vstring_truncate(vp, --len);
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

 /* auth_key_aes_decrypt - Rijndael-128 CBC, PBKDF2-SHA1 (mail.admin.api) */

static int auth_key_aes_decrypt(const char *pass_phrase, const char *cipher_b64,
			            VSTRING *plain_out)
{
    const char *myname = "auth_key_aes_decrypt";
    VSTRING *raw = vstring_alloc(64);
    const unsigned char *buf;
    ssize_t buf_len;
    const unsigned char *salt;
    const unsigned char *iv;
    const unsigned char *cipher;
    ssize_t cipher_len;
    unsigned char key[AUTH_KEY_SALT_IV_BYTES];
    unsigned char *outbuf;
    int     out_len;
    int     final_len;
    int     ret = -1;
    EVP_CIPHER_CTX *ctx = 0;

    VSTRING_RESET(plain_out);
    if (pass_phrase == 0 || *pass_phrase == 0 || cipher_b64 == 0 || *cipher_b64 == 0)
	return (-1);
    if (base64_decode(raw, cipher_b64, (ssize_t) strlen(cipher_b64)) == 0)
	return (-1);
    buf = (const unsigned char *) STR(raw);
    buf_len = LEN(raw);
    if (buf_len < AUTH_KEY_SALT_IV_BYTES * 2 + 1)
	return (-1);
    salt = buf;
    iv = buf + AUTH_KEY_SALT_IV_BYTES;
    cipher = buf + AUTH_KEY_SALT_IV_BYTES * 2;
    cipher_len = buf_len - AUTH_KEY_SALT_IV_BYTES * 2;
    if (PKCS5_PBKDF2_HMAC_SHA1(pass_phrase, (int) strlen(pass_phrase),
			       salt, AUTH_KEY_SALT_IV_BYTES,
			       AUTH_KEY_DERIV_ITERATIONS,
			       AUTH_KEY_SALT_IV_BYTES, key) != 1)
	return (-1);
    outbuf = (unsigned char *) mymalloc(cipher_len + AUTH_KEY_SALT_IV_BYTES);
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == 0)
	goto cleanup;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), 0, key, iv) != 1
	|| EVP_DecryptUpdate(ctx, outbuf, &out_len, cipher, (int) cipher_len) != 1
	|| EVP_DecryptFinal_ex(ctx, outbuf + out_len, &final_len) != 1) {
	if (msg_verbose)
	    msg_info("%s: decrypt failed", myname);
	goto cleanup;
    }
    vstring_strncat(plain_out, (const char *) outbuf, out_len + final_len);
    auth_key_trim_trailing_space(plain_out);
    ret = 0;

cleanup:
    if (ctx)
	EVP_CIPHER_CTX_free(ctx);
    if (outbuf)
	myfree(outbuf);
    vstring_free(raw);
    return (ret);
}

#endif

 /* auth_key_check_plain - {PLAIN} */

static int auth_key_check_plain(const char *expected, const char *bearer)
{
    return (auth_key_str_equal(expected, bearer));
}

#ifdef USE_TLS

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

 /* auth_key_check_aes - {AES-256-CBC} */

static int auth_key_check_aes(const char *cipher_b64, const char *bearer,
			              MAPS *salt_maps)
{
    const char *pass_phrase;
    VSTRING *plain = vstring_alloc(64);

    if (salt_maps == 0)
	return (0);
    pass_phrase = maps_find(salt_maps, AUTH_KEY_AES_SCHEME, 0);
    if (salt_maps->error != 0 || pass_phrase == 0 || *pass_phrase == 0)
	return (0);
    if (auth_key_aes_decrypt(pass_phrase, cipher_b64, plain) != 0) {
	vstring_free(plain);
	return (0);
    }
    if (!auth_key_str_equal(STR(plain), bearer)) {
	vstring_free(plain);
	return (0);
    }
    vstring_free(plain);
    return (1);
}

#endif

 /* auth_key_scheme_match - validate one {scheme}payload entry */

static int auth_key_scheme_match(const char *scheme, ssize_t scheme_len,
			         const char *payload, ssize_t payload_len,
			         const char *bearer, MAPS *salt_maps)
{
    char   *scheme_buf;
    char   *payload_buf;
    int     match = 0;

    while (payload_len > 0
	   && ((unsigned char) payload[payload_len - 1]) <= ' ')
	payload_len--;
    scheme_buf = mystrndup(scheme, scheme_len);
    payload_buf = mystrndup(payload, payload_len);

#ifdef USE_TLS
    if (strcasecmp(scheme_buf, AUTH_KEY_PLAIN_SCHEME) == 0)
	match = auth_key_check_plain(payload_buf, bearer);
    else if (strcasecmp(scheme_buf, AUTH_KEY_SHA1_SCHEME) == 0)
	match = auth_key_check_sha1_hex(payload_buf, bearer);
    else if (strcasecmp(scheme_buf, AUTH_KEY_AES_SCHEME) == 0)
	match = auth_key_check_aes(payload_buf, bearer, salt_maps);
    else
	msg_warn("postapi: unknown auth key scheme \"%s\"", scheme_buf);
#else
    if (strcasecmp(scheme_buf, AUTH_KEY_PLAIN_SCHEME) == 0)
	match = auth_key_check_plain(payload_buf, bearer);
    else
	msg_warn("postapi: auth key scheme \"%s\" requires TLS/OpenSSL build",
		 scheme_buf);
#endif

    myfree(scheme_buf);
    myfree(payload_buf);
    return (match);
}

 /* auth_key_validate - parse map value and compare bearer token */

int     auth_key_validate(const char *map_value, const char *bearer_token,
			          MAPS *salt_maps)
{
    const char *cp;
    int     saw_entry = 0;
    int     format_err = 0;

    if (map_value == 0 || *map_value == 0 || bearer_token == 0)
	return (AUTH_KEY_FORMAT_ERR);

    cp = map_value;
    for (;;) {
	while (auth_key_delim(*cp))
	    cp++;
	if (*cp == 0)
	    break;
	if (*cp != '{') {
	    format_err = 1;
	    break;
	}
	cp++;
	{
	    const char *scheme = cp;

	    while (*cp && *cp != '}')
		cp++;
	    if (*cp != '}') {
		format_err = 1;
		break;
	    }
	    cp++;
	    {
		const char *payload = cp;
		const char *payload_end = cp;

		while (*payload_end && *payload_end != '{'
		       && !auth_key_delim(*payload_end))
		    payload_end++;
		if (scheme < cp - 1 && payload_end > payload) {
		    ssize_t scheme_len = (cp - 1) - scheme;
		    ssize_t payload_len = payload_end - payload;

		    saw_entry = 1;
		    if (auth_key_scheme_match(scheme, scheme_len,
					      payload, payload_len,
					      bearer_token, salt_maps))
			return (AUTH_KEY_OK);
		}
		cp = payload_end;
	    }
	}
    }
    if (format_err)
	return (AUTH_KEY_FORMAT_ERR);
    if (!saw_entry)
	return (AUTH_KEY_FORMAT_ERR);
    return (AUTH_KEY_MISMATCH);
}
