/*++
/* NAME
/*	cryptmaps 3
/* SUMMARY
/*	expand {scheme}payload map lookup results
/* SYNOPSIS
/*	#include <cryptmaps.h>
/*
/*	void	cryptmaps_init()
/*
/*	const char *cryptmaps_expand(value)
/*	const char *value;
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
#include <dict.h>
#include <maps.h>

#include <mail_params.h>
#include <cryptmaps.h>

#ifdef USE_TLS
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#define CRYPTMAPS_AES_SCHEME		"AES-256-CBC"
#define CRYPTMAPS_PLAIN_SCHEME		"PLAIN"
#define CRYPTMAPS_SHA1_SCHEME		"SHA1.HEX"
#define CRYPTMAPS_DERIV_ITERATIONS	1000
#define CRYPTMAPS_SALT_IV_BYTES		16

#define STR(x)	vstring_str(x)
#define LEN(x)	VSTRING_LEN(x)

static MAPS *cryptmaps_salt_maps;
static VSTRING *cryptmaps_result;

 /* cryptmaps_delim - entry separator */

static int cryptmaps_delim(int ch)
{
    return (ch == 0 || ch == ',' || ch == '\n' || ch == '\r' || ch == '\t'
	    || ch == ' ');
}

 /* cryptmaps_trim_trailing_space - match C# DecryptWithTrim */

static void cryptmaps_trim_trailing_space(VSTRING *vp)
{
    ssize_t len = LEN(vp);

    while (len > 0 && ((unsigned char) STR(vp)[len - 1]) <= ' ')
	vstring_truncate(vp, --len);
}

#ifdef USE_TLS

 /* cryptmaps_decode_cipher - base64 with hex fallback */

static int cryptmaps_decode_cipher(const char *cipher_text, VSTRING *raw)
{
    ssize_t len;

    VSTRING_RESET(raw);
    if (cipher_text == 0 || *cipher_text == 0)
	return (-1);
    len = (ssize_t) strlen(cipher_text);
    if (base64_decode(raw, cipher_text, len) != 0 && LEN(raw) > 0)
	return (0);
    VSTRING_RESET(raw);
    if (hex_decode(raw, cipher_text, len) != 0 && LEN(raw) > 0)
	return (0);
    return (-1);
}

 /* cryptmaps_aes_decrypt - Rijndael-128 CBC, PBKDF2-SHA1 (mail.admin.api) */

static int cryptmaps_aes_decrypt(const char *pass_phrase, const char *cipher_text,
			             VSTRING *plain_out)
{
    const char *myname = "cryptmaps_aes_decrypt";
    VSTRING *raw = vstring_alloc(64);
    const unsigned char *buf;
    ssize_t buf_len;
    const unsigned char *salt;
    const unsigned char *iv;
    const unsigned char *cipher;
    ssize_t cipher_len;
    unsigned char key[CRYPTMAPS_SALT_IV_BYTES];
    unsigned char *outbuf;
    int     out_len;
    int     final_len;
    int     ret = -1;
    EVP_CIPHER_CTX *ctx = 0;

    VSTRING_RESET(plain_out);
    if (pass_phrase == 0 || *pass_phrase == 0)
	return (-1);
    if (cryptmaps_decode_cipher(cipher_text, raw) != 0)
	return (-1);
    buf = (const unsigned char *) STR(raw);
    buf_len = LEN(raw);
    if (buf_len < CRYPTMAPS_SALT_IV_BYTES * 2 + 1)
	return (-1);
    salt = buf;
    iv = buf + CRYPTMAPS_SALT_IV_BYTES;
    cipher = buf + CRYPTMAPS_SALT_IV_BYTES * 2;
    cipher_len = buf_len - CRYPTMAPS_SALT_IV_BYTES * 2;
    if (PKCS5_PBKDF2_HMAC_SHA1(pass_phrase, (int) strlen(pass_phrase),
			       salt, CRYPTMAPS_SALT_IV_BYTES,
			       CRYPTMAPS_DERIV_ITERATIONS,
			       CRYPTMAPS_SALT_IV_BYTES, key) != 1)
	return (-1);
    outbuf = (unsigned char *) mymalloc(cipher_len + CRYPTMAPS_SALT_IV_BYTES);
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
    cryptmaps_trim_trailing_space(plain_out);
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

 /* cryptmaps_salt_lookup - dict_get without maps_find recursion */

static const char *cryptmaps_salt_lookup(const char *key)
{
    char  **map_name;
    DICT   *dict;
    const char *value;

    if (cryptmaps_salt_maps == 0)
	return (0);
    for (map_name = cryptmaps_salt_maps->argv->argv; *map_name; map_name++) {
	if ((dict = dict_handle(*map_name)) == 0)
	    continue;
	if ((value = dict_get(dict, key)) != 0 && *value != 0)
	    return (value);
	if (dict->error != 0)
	    break;
    }
    return (0);
}

 /*
  * cryptmaps_expand_segment - transform one {scheme}payload entry.
  * Returns 1 when output was appended, 0 for passthrough, -1 on error.
  */

static int cryptmaps_expand_segment(const char *scheme, const char *payload,
				            ssize_t payload_len, VSTRING *out)
{
    char   *payload_buf;

    while (payload_len > 0
	   && ((unsigned char) payload[payload_len - 1]) <= ' ')
	payload_len--;
    if (strcasecmp(scheme, CRYPTMAPS_PLAIN_SCHEME) == 0) {
	if (payload_len > 0)
	    vstring_strncat(out, payload, payload_len);
	return (1);
    }
#ifdef USE_TLS
    if (strcasecmp(scheme, CRYPTMAPS_AES_SCHEME) == 0) {
	const char *pass_phrase;
	VSTRING *plain = vstring_alloc(64);

	if (payload_len <= 0) {
	    vstring_free(plain);
	    msg_warn("cryptmaps: empty %s payload", CRYPTMAPS_AES_SCHEME);
	    return (-1);
	}
	pass_phrase = cryptmaps_salt_lookup(CRYPTMAPS_AES_SCHEME);
	if (pass_phrase == 0) {
	    vstring_free(plain);
	    msg_warn("cryptmaps: %s is not set or has no \"%s\" entry",
		     VAR_ACCESS_SALT_MAPS, CRYPTMAPS_AES_SCHEME);
	    return (-1);
	}
	payload_buf = mystrndup(payload, payload_len);
	if (cryptmaps_aes_decrypt(pass_phrase, payload_buf, plain) != 0) {
	    myfree(payload_buf);
	    vstring_free(plain);
	    msg_warn("cryptmaps: %s decrypt failed", CRYPTMAPS_AES_SCHEME);
	    return (-1);
	}
	myfree(payload_buf);
	vstring_strncat(out, STR(plain), LEN(plain));
	vstring_free(plain);
	return (1);
    }
#else
    if (strcasecmp(scheme, CRYPTMAPS_AES_SCHEME) == 0) {
	msg_warn("cryptmaps: %s requires TLS/OpenSSL build", CRYPTMAPS_AES_SCHEME);
	return (-1);
    }
#endif
    return (0);
}

 /* cryptmaps_init - open access_salt_maps */

void    cryptmaps_init(void)
{
    if (cryptmaps_salt_maps != 0)
	return;
    if (*var_access_salt_maps == 0)
	return;
    cryptmaps_salt_maps = maps_create("access salt",
				      var_access_salt_maps,
				      DICT_FLAG_LOCK | DICT_FLAG_FOLD_FIX);
}

 /* cryptmaps_expand - expand {scheme}payload entries */

const char *cryptmaps_expand(const char *value)
{
    const char *cp;
    const char *myname = "cryptmaps_expand";

    if (value == 0 || *value == 0)
	return (value);
    if (strchr(value, '{') == 0)
	return (value);
    if (cryptmaps_result == 0)
	cryptmaps_result = vstring_alloc(64);
    VSTRING_RESET(cryptmaps_result);

    cp = value;
    for (;;) {
	while (cryptmaps_delim(*cp))
	    vstring_strncat(cryptmaps_result, cp++, 1);
	if (*cp == 0)
	    break;
	if (*cp != '{') {
	    const char *literal = cp;

	    while (*cp && *cp != '{')
		cp++;
	    vstring_strncat(cryptmaps_result, literal, cp - literal);
	    continue;
	}
	{
	    const char *seg_start = cp;
	    const char *scheme;
	    ssize_t scheme_len;
	    const char *payload;
	    const char *payload_end;
	    ssize_t payload_len;
	    char   *scheme_buf;
	    int     expand_st;

	    cp++;
	    scheme = cp;
	    while (*cp && *cp != '}')
		cp++;
	    if (*cp != '}' || scheme == cp) {
		msg_warn("%s: malformed macro in map value", myname);
		return (0);
	    }
	    scheme_len = cp - scheme;
	    cp++;
	    payload = cp;
	    payload_end = cp;
	    while (*payload_end && *payload_end != '{'
		   && !cryptmaps_delim(*payload_end))
		payload_end++;
	    payload_len = payload_end - payload;
	    scheme_buf = mystrndup(scheme, scheme_len);
	    expand_st = cryptmaps_expand_segment(scheme_buf, payload,
						 payload_len, cryptmaps_result);
	    myfree(scheme_buf);
	    if (expand_st < 0)
		return (0);
	    if (expand_st == 0)
		vstring_strncat(cryptmaps_result, seg_start,
				payload_end - seg_start);
	    cp = payload_end;
	}
    }
    return (STR(cryptmaps_result));
}
