/*
 * Apache Module for OpenIAM Authenticaton an reverse-proxying
 * Author: Evgeniy Sergeev, <evgeniy.sereev@gmail.com> OpenIAM LLC
 */

/* Copyrigth from old mod_authnz_openiam.c
 * Apache OpenIAM Authentication and Authorization Module
 * Author: Lars Nilsen, OpenIAM LLC
 */

/* Copyrigth from old mod_iam_authn.c
 * Apache Module for Authentication
 * Author: Sona Petrosyan, OpenIAM LLC
 */

/* Copyright from mod_auth_kerb.c */
/*
 * Daniel Kouril <kouril@users.sourceforge.net>
 *
 * Source and Documentation can be found at:
 * http://modauthkerb.sourceforge.net/
 *
 * Based on work by
 *   James E. Robinson, III <james@ncstate.net>
 *   Daniel Henninger <daniel@ncsu.edu>
 *   Ludek Sulak <xsulak@fi.muni.cz>
 */

/* Copyright from mod_substitute.c */
/*
 * Copyright (c) 2004-2006 Masarykova universita
 * (Masaryk University, Brno, Czech Republic)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the University nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>
#include <mod_auth.h>
#include <mod_proxy.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_date.h>
#include <apr_base64.h>
#include <apr_thread_mutex.h>
#include <apr_atomic.h>
#ifdef MEMCACHE_CACHE
#include <apr_memcache.h>
#endif
#include <ap_config.h>
#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "version.h"
#include "debug_dump_options.h"
#include "parse_soap_xml.h"
#include <curl/curl.h>
#include "curl_recv_data.h"
#include "str_utils.h"
#include "debug_utils.h"
#include "date_utils.h"
#include "iam_errors.h"
#include "iam_substitute.h" /* for substitute */
#include "esb_api.h"
#include "shared_mem.h"
#include "read_cert.h"
#include "parse_cert_response.h"

/* Kerberos */
#include <krb5.h>
#ifdef HEIMDAL
#  include <gssapi.h>
#else
#  include <gssapi/gssapi.h>
#  include <gssapi/gssapi_generic.h>
#  include <gssapi/gssapi_krb5.h>
#  define GSS_C_NT_USER_NAME gss_nt_user_name
#  define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  define GSS_KRB5_NT_PRINCIPAL_NAME gss_nt_krb5_name
#  define krb5_get_err_text(context,code) error_message(code)
#  include "mit-internals.h" /* Needed to work around problems with replay caches */
#endif
#ifndef GSSAPI_SUPPORTS_SPNEGO
#  include "spnegokrb5.h"
#endif
/* !Kerberos */
#include <unistd.h> /* for close and unlink functions */

#ifdef MEMCACHE_CACHE
#include "memcache_utils.h"
#endif

#define MECH_NEGOTIATE "Negotiate"
#define SERVICE_NAME   "HTTP"
#ifndef KRB5_LIB_FUNCTION
#  if defined(_WIN32)
#    define KRB5_LIB_FUNCTION _stdcall
#  else
#    define KRB5_LIB_FUNCTION
#  endif
#endif

/* apache version 2.4 and 2.2 defines helper */
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER >= 4
#define APACHE_24
#endif

/* for authentication */
#define AUTH_TYPE_OPENIAM_OLD         "IAMToken"
#define AUTH_TYPE_OPENIAM             "OpenIAM"
#define AUTH_TYPE_OPENIAM_NOAUTH      "OpenIAM-NoAuth"
#define OPENIAM_AUTH_ANONYMOUS_NAME   "AnonimousUser@OpeniamNoAuth.r-proxy.internal"

/* HTTP and HTML strings */
static const char s_domain[]               = "Domain=";
static const char s_location[]             = "Location";
static const char s_content_location[]     = "Content-Location";
static const char s_uri[]                  = "URI";
static const char s_destination[]          = "Destination";
static const char s_set_cookie[]           = "Set-Cookie";
static const char s_cookie[]               = "Cookie";

/* OpenIAM HTTP headers */
static const char s_pattern_id_header[]    = "X-OpenIAM-URI-Pattern-Id";
static const char s_cp_id_header[]         = "X-OpenIAM-CP-Id";
static const char s_proxy_host_header[]    = "X-OpenIAM-Proxy-Host";
static const char s_proxy_scheme_header[]  = "X-OpenIAM-Proxy-Scheme";
static const char s_auth_header[]          = "x-openiam-auth-token";
static const char s_client_cert_header[]   = "X-OpenIAM-Client-Cert";

/* additional apache filters */
static const char s_fix_headers_filter_name[]   = "IamHead";
static const char s_fix_content_filter_name[]   = "IamFix";
static const char s_post_form_filter_name[]     = "IamForm";
static const char s_post_form_output_name[]     = "IamFormRedirect";

#define NOTE_FORM_POST_DATA                     "OPENIAM_FormPostData"
#define NOTE_GENERATE_FORM_POST                 "OPENIAM_GenerateFormPost"
#define NOTE_GENERATE_FORM_POST_DATA            "OPENIAM_GenerateFormPostData"
#define NOTE_PROPAGATE_HEADERS                  "OPENIAM_SetHeaders"
#define NOTE_PROPAGATE_COOKIES                  "OPENIAM_SetCookies"
#define NOTE_CLEAN_AUTH_INFO                    "OPENIAM_CleanAuthInfo"

#define OPENIAM_DEFAULT_BOUNDIARY               "OPENIAM0123456789ABCDEFGHIJKLMNOPQRSTadfjkqrew789afsdj";

/* ESB services */
#define ESB_SERVICE_AUTH        "/openiam-esb/idmsrvc/AuthenticationService"
#define ESB_KEY_MANAGEMENT      "/openiam-esb/idmsrvc/KeyManagementWS"
#define ESB_FEDERATION          "/openiam-esb/idmsrvc/URIFederationWebService"
#define ESB_CERT                "/openiam-esb/auth/proxy/cert/identity"

/* encrypt/decrypt */

static const int iv_size = 16;

/* main module structure */

module AP_MODULE_DECLARE_DATA iam_authn_module;


typedef struct {
	const char  *esb_server_name;
	const char  *ui_server_name;

	const char  *service_auth;
	const char  *service_key_management;
	const char  *service_federation;
	const char  *service_cert;

	const char  *login_url;
	const char  *postback_param;
	const char  *logout_url;

	apr_table_t *expired_headers;
	apr_table_t *missing_auth_headers;
	apr_table_t *logout_headers;

	apr_pool_t  *auth_cookie_pool;
	const char  *auth_cookie_name;
	ap_regex_t  *auth_cookie_regexp;
	const char  *auth_cookie_domain;

	const char  *path;             /* path needed for ProxyPassReverse pass to mod_proxy */

	/* workaround for ';' in redirect from jenkins */ 
	const char  *ignore_invalid_chars_in_redirect;

	/* Kerberos (from mod_auth_kerb) */
	int          krb_enabled;
	const char  *krb_service_name;
	int          krb_save_credentials;
	const char  *krb_auth_realms;
	char        *krb_keytab;
	int          krb_verify_kdc;
	int          krb_principal_only;
	const char  *krb_principal_suffix;
	const char  *krb_principal_prefix;
	/* end of Kerberos config */

	int          max_time_difference; /* in ms */

	/* helper to use proxy on http and proxied server on https and server on http but proxy on https */
	int          is_send_scheme;

	/* Debugging */
	int          is_verbose;       /* log verbose info */
	int          is_dump_requests; /* dump each request in log */
	int          is_dump_response; /* dump each response */
	int          is_dump_curl;
	int          is_debug_cookies; /* dump cookies and crypt info */
	int          is_debug_filters; /* dump reverse filters */
	int          is_debug_kerb;    /* dump kerberos authentication in logs */
	int          is_debug_cert;    /* dump certificate authentication in logs */

	/* URI patterns Authentication override lists */
	apr_array_header_t  *noauth_uri_list;
	apr_array_header_t  *noauth_prefix_list;
	apr_array_header_t  *noauth_suffix_list;

	/* URI patterns disable r-proxy lists */
	apr_array_header_t  *exclude_uri_list;
	apr_array_header_t  *exclude_prefix_list;

	/* Use simple cache key names for URIs that have prefixes from this list*/
	apr_array_header_t  *simple_cache_uri_list;

	/* Substitute patterns */
	apr_array_header_t  *patterns;

	/* Various redirects */
	apr_array_header_t  *redirects;
	apr_array_header_t  *redirects_before_auth;
	apr_array_header_t  *target_servers; /* redirect not to server from ESB response but to diferent server */ 
	const char          *on_auth_redirect;
	const char          *on_fail_redirect;
	const char          *on_logout_redirect;
	const char          *on_logout_redirect_cookie;
	ap_regex_t          *on_logout_redirect_cookie_regexp;
	const char          *internal_leave_link;
	int                  logout_redirect_enabled;
	const char          *app_link_for_logout_redirect;

	/* form-multipart in POST */
	const char          *multipart_str; /* if NULL, used form-url-encoded */
	apr_table_t         *multipart_urls;

	/* support for .net aspx __VIEWSTATE and __EVENTVALIDATION in form posts */
	const char          *viewstate_str;          // __VIEWSTATE
	const char          *viewstategenerator_str; // __VIEWSTATEGENERATOR
	const char          *eventvalidation_str;    // __EVENTVALIDATION
	const char          *eventtarget_str;        // __EVENTTARGET
	const char          *eventargument_str;      // __EVENTARGUMENT
	const char          *html_form_action_str;
	int                  viewstate_follow_location;

	apr_array_header_t  *viewstate_urls_list;
	apr_array_header_t  *unset_allcookies_list;
	apr_table_t         *skip_form_post_if_cookie_present;

	/* limit sending FORM POST only to URIs from this list */
	apr_array_header_t  *form_post_paths;
	apr_array_header_t  *generate_form_post_paths;

	/* Under Construction redirect */
	char                *under_construction_redirect;
	char                *under_construction_backend;

	/* encryption */
	const unsigned char *evp_key;
	volatile int         evp_key_length;

	/* cert auth */
	int                  do_not_generate_cookie_for_cert_auth;
	int                  read_client_cert_from_header;
	char                *client_cert_header_name;

	/* r-proxy timeout */
	int                  rproxy_timeout;
	int                  rproxy_ttl;

	CURL           *curl_session;
	CURL           *curl_fetch_session;

} iam_authn_dir_config_rec;


typedef struct {
	apr_time_t           tokens_expiration_time;
	apr_time_t           noauth_expiration_time;
	apr_time_t           esb_expiration_time;

#ifdef MEMCACHE_CACHE
	/* memcache cache */
	int                     memcache_esb_caching;
	volatile apr_uint32_t   memcache_hit;
	volatile apr_uint32_t   memcache_miss;
	apr_memcache_server_t  *memcache_server;
	apr_memcache_t         *memcache_handle;
	const char             *memcache_host;
	int                     memcache_port;
#endif

#ifdef SHARED_CACHE
	int                     shared_esb_caching;
	shared_cache_t*         sc;
	shared_cache_t*         tokens_sc;
	apr_size_t              shared_global_size;
	apr_size_t              shared_size;
	int                     shared_sync_time;
	int                     shared_cleanup;
	volatile apr_uint32_t   shared_hit;
	volatile apr_uint32_t   shared_miss;
	volatile apr_uint32_t   tokens_shared_hit;
	volatile apr_uint32_t   tokens_shared_miss;
#endif
	int          is_dump_caching;  /* log caching */

	const char          *redirect_overwrite;
	const char          *proxypass_reverse;
	apr_array_header_t  *login_redirects;

} iam_authn_server_config_rec;

typedef struct {
	const char* pattern;
	size_t      pattern_length;
	const char* backend;
} map_rec;

typedef struct {
	const char* from;
	const char* to;
} redirect_rec;

typedef struct {
	const char* from;
	const char* to;
} replace_rec;

typedef struct {
	const char     *user_id;
	const char     *backend_url;
	EVP_CIPHER_CTX *evp_ctx;
	const char     *ralias_real; /* USED in filters chain after mod_proxy. to fix headers, cookies and redirects */
	const char     *ralias_fake;
	const char     *cookie_fake;

	int             no_auth;
	int             password_auth;
	int             cert_auth;
	int             kerb_auth;

	char           *redirected;

	apr_table_t    *arguments;

	apr_array_header_t    *form_fields;
} iam_authn_request_config_rec;

/* Kerberos: from mod_auth_kerb */
typedef struct {
	char *authline;
	char *user;
	char *mech;
	int   last_return;
} krb5_conn_data;


/* Kerberos config */

static const char* set_krb_realms(cmd_parms *cmd, void *cfg, const char *arg)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	dir_config->krb_auth_realms = arg;
	return NULL;
}
/* end of Kerberos config */

static void set_and_comp_regexp(iam_authn_dir_config_rec* dir_config, apr_pool_t *p, const char *cookie_name);
static void set_auth_cookie_domain(iam_authn_dir_config_rec* dir_config, const char *domain);

/* deprecated options */

static const char* set_cookie_secure_deprecated(cmd_parms *parms, void *cfg, const char *flag)
{
	ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, parms->server, "OPENIAM_CookieSecure deprecated. Cookies always encrypted");
	return NULL;
}

static const char *set_cookie_name(cmd_parms *parms, void *cfg, const char *name)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	set_and_comp_regexp(dir_config, parms->pool, name);
	return NULL;
}

static const char *set_cookie_domain(cmd_parms *parms, void *cfg, const char *domain)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	set_auth_cookie_domain(dir_config, domain);
	return NULL;
}

/* end of deprecated functions */

static const char* cmd_set_openiam_version(cmd_parms *parms, void *cfg, const char *version)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	if ( strcmp(version, "3") != 0 ) {
		return "Supported only OpenIAM version 3";
	}
	return NULL;
}


static const char* cmd_set_tokens_expire(cmd_parms *parms, void *cfg, const char *time)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->tokens_expiration_time = apr_time_from_sec(apr_atoi64(time));
	return NULL;
}

static const char* cmd_set_esb_expire(cmd_parms *parms, void *cfg, const char *time)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->esb_expiration_time = apr_time_from_sec(apr_atoi64(time));
	return NULL;
}

static const char* cmd_set_noauth_expire(cmd_parms *parms, void *cfg, const char *time)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->noauth_expiration_time = apr_time_from_sec(apr_atoi64(time));
	return NULL;
}

static const char* cmd_set_dump_caching(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	if ( strcasecmp( value, "on" ) == 0 ) { 
		server_config->is_dump_caching = 1;
	} else {
		server_config->is_dump_caching = 0;
	}
	return NULL;
}

#ifdef SHARED_CACHE

static const char* cmd_set_shared_esb_caching(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	if ( strcasecmp( value, "on" ) == 0 ) { 
		server_config->shared_esb_caching = 1;
	} else {
		server_config->shared_esb_caching = 0;
	}
	return NULL;
}

static const char* cmd_set_shared_global_size(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->shared_global_size = apr_atoi64(value);
	return NULL;
}

static const char* cmd_set_shared_size(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->shared_size = apr_atoi64(value);
	return NULL;
}

static const char* cmd_set_shared_cleanup(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	if ( strcasecmp( value, "on" ) == 0 ) { 
		server_config->shared_cleanup = 1;
	} else {
		server_config->shared_cleanup = 0;
	}
	return NULL;
}

static const char* cmd_set_shared_sync_time(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->shared_sync_time = apr_atoi64(value);
	return NULL;
}

#endif

#ifdef MEMCACHE_CACHE

static const char* cmd_set_memcache_esb_caching(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	if ( strcasecmp( value, "on" ) == 0 ) { 
		server_config->memcache_esb_caching = 1;
	} else {
		server_config->memcache_esb_caching = 0;
	}
	return NULL;
}

static const char* cmd_set_memcache_host(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->memcache_host = value;
	return NULL;
}

static const char* cmd_set_memcache_port(cmd_parms *parms, void *cfg, const char *value)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->memcache_port = apr_atoi64(value);
	return NULL;
}

#endif

static const char* cmd_set_headers_at_expiration(cmd_parms *parms, void *cfg, const char *header_name, const char *header_value)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;

	apr_table_set(dir_config->expired_headers, header_name, header_value);

	return NULL;
}

static const char* cmd_set_headers_at_missing_auth(cmd_parms *parms, void *cfg, const char *header_name, const char *header_value)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;

	apr_table_set(dir_config->missing_auth_headers, header_name, header_value);

	return NULL;
}

static const char* cmd_set_headers_at_logout(cmd_parms *parms, void *cfg, const char *header_name, const char *header_value)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;

	apr_table_set(dir_config->logout_headers, header_name, header_value);

	return NULL;
}

static const char* cmd_set_multipart_string_for_uri(cmd_parms *parms, void *cfg, const char *uri, const char *multipart_str)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;

	apr_table_set(dir_config->multipart_urls, uri, multipart_str);

	return NULL;
}


static const char* cmd_set_skip_form_post_if_cookie(cmd_parms *parms, void *cfg, const char *uri, const char *cookie_name)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;

	apr_table_set(dir_config->skip_form_post_if_cookie_present, uri, cookie_name);

	return NULL;
}


static const char* cmd_set_target_server(cmd_parms *parms, void *cfg,
                                         const char *uri, const char *backend)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->target_servers);
	item->pattern        = uri;
	item->pattern_length = strlen(uri);
	item->backend        = backend;
	return NULL;
}


static const char* cmd_set_form_post_uri(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	*(const char**)apr_array_push(dir_config->form_post_paths) = uri;
	return NULL;
}

static const char* cmd_set_generate_form_post_page(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	*(const char**)apr_array_push(dir_config->generate_form_post_paths) = uri;
	return NULL;
}

static const char* cmd_set_unset_allcookies(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->unset_allcookies_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = NULL;
	return NULL;
}

static const char* cmd_set_viewstate_url(cmd_parms *parms, void *cfg, const char *uri, const char *url)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->viewstate_urls_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = url;
	return NULL;
}

static const char* cmd_set_under_construction(cmd_parms *parms, void *cfg, const char *uri, const char *backend)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	dir_config->under_construction_redirect = (char*)uri;
	dir_config->under_construction_backend  = (char*)backend;
	return NULL;
}

static const char* cmd_set_exclude_uri(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->exclude_uri_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = NULL;
	return NULL;
}

static const char* cmd_set_simple_cache_uri(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->simple_cache_uri_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = NULL;
	return NULL;
}

static const char* cmd_set_exclude_prefix(cmd_parms *parms, void *cfg, const char *uri)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->exclude_prefix_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = NULL;
	return NULL;
}


static const char* cmd_set_noauth_uri_with_backend(cmd_parms *parms, void *cfg, 
                                                   const char *uri, const char *backend)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->noauth_uri_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = backend;
	return NULL;
}

static const char* cmd_set_noauth_uri(cmd_parms *parms, void *cfg, const char *uri)
{
	return cmd_set_noauth_uri_with_backend(parms, cfg, uri, NULL);
}

static const char* cmd_set_noauth_prefix_with_backend(cmd_parms *parms, void *cfg, 
                                                   const char *uri, const char *backend)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->noauth_prefix_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = backend;
	return NULL;
}

static const char* cmd_set_noauth_prefix(cmd_parms *parms, void *cfg, const char *uri)
{
	return cmd_set_noauth_prefix_with_backend(parms, cfg, uri, NULL);
}

static const char* cmd_set_noauth_suffix_with_backend(cmd_parms *parms, void *cfg, 
                                                   const char *uri, const char *backend)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	map_rec* item = (map_rec*)apr_array_push(dir_config->noauth_suffix_list);
	item->pattern          = uri;
	item->pattern_length   = strlen(uri);
	item->backend          = backend;
	return NULL;
}

static const char* cmd_set_noauth_suffix(cmd_parms *parms, void *cfg, const char *uri)
{
	return cmd_set_noauth_suffix_with_backend(parms, cfg, uri, NULL);
}

static const char* cmd_set_redirects(cmd_parms *parms, void *cfg, const char *arg, const char *arg2)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	redirect_rec* item = (redirect_rec*)apr_array_push(dir_config->redirects);
	item->from = arg;
	item->to   = arg2;
	return NULL;
}

static const char* cmd_set_redirects_before_auth(cmd_parms *parms, void *cfg, const char *arg, const char *arg2)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	redirect_rec* item = (redirect_rec*)apr_array_push(dir_config->redirects_before_auth);
	item->from = arg;
	item->to   = arg2;
	return NULL;
}

static const char* cmd_set_login_redirect(cmd_parms *parms, void *cfg, const char *arg, const char *arg2)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	redirect_rec* item = (redirect_rec*)apr_array_push(server_config->login_redirects);
	item->from = arg;
	item->to   = arg2;
	return NULL;
}

static const char* cmd_set_substitute(cmd_parms *cmd, void *cfg, const char *arg)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	return iam_subst_set_pattern(cmd->pool, dir_config->patterns, arg);
}



/* dcfg->regexp is "^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)",
 * which has three subexpressions, $0..$2 */
#define NUM_SUBS 3

static void set_and_comp_regexp(iam_authn_dir_config_rec* dir_config, apr_pool_t *p, const char *cookie_name)
{
	if ( dir_config->auth_cookie_regexp && dir_config->auth_cookie_name
		&& ( strcasecmp(dir_config->auth_cookie_name, cookie_name) == 0) ) {
		ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, NULL, "auth cookie name %s already set", cookie_name);
		return; // it is already set.
	}
	// clean up all.
	dir_config->auth_cookie_name   = NULL;
	dir_config->auth_cookie_regexp = NULL;
	if ( dir_config->auth_cookie_pool ) {
		if ( dir_config->auth_cookie_pool != p ) {
			apr_pool_clear(dir_config->auth_cookie_pool);
		}
	} else {
		apr_pool_t *new_pool = NULL;
		if ( apr_pool_create(&new_pool, p) == APR_SUCCESS && new_pool ) {
			dir_config->auth_cookie_pool = new_pool;
		} else {
			dir_config->auth_cookie_pool = p;
		}
	}

	if ( dir_config->is_verbose ) {
		ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, NULL, "set auth cookie name %s", cookie_name);
	}

	int danger_chars = 0;
	const char *saved_cookie_name = cookie_name;
	const char *sp = cookie_name;
	const char* regexp_string;
	/* The goal is to end up with this regexp,
	 * ^cookie_name=([^;,]+)|[;,][ \t]+cookie_name=([^;,]+)
	 * with cookie_name obviously substituted either
	 * with the real cookie name set by the user in httpd.conf, or with the
	 * default COOKIE_NAME. */
	/* Anyway, we need to escape the cookie_name before pasting it
	 * into the regex
	 */
	while ( *sp ) {
		if ( !apr_isalnum(*sp) ) {
			++danger_chars;
		}
        ++sp;
	}
	if ( danger_chars ) {
		char *cp = apr_palloc(dir_config->auth_cookie_pool, sp - cookie_name + danger_chars + 1); /* 1 == \0 */
		sp = cookie_name;
		cookie_name = cp;
		while ( *sp ) {
			if ( !apr_isalnum(*sp) ) {
				*cp++ = '\\';
			}
			*cp++ = *sp++;
		}
		*cp = '\0';
	}
	dir_config->auth_cookie_name   = NULL;
	dir_config->auth_cookie_regexp = NULL;
	regexp_string = apr_pstrcat(dir_config->auth_cookie_pool, "^", cookie_name, "=([^;,]+)|[;,][ \t]*", cookie_name, "=([^;,]+)", NULL);
	//ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "regexp string is %s", regexp_string);
	if ( regexp_string ) {
		dir_config->auth_cookie_regexp = ap_pregcomp(dir_config->auth_cookie_pool, regexp_string, AP_REG_EXTENDED);
	}
	if ( dir_config->auth_cookie_regexp && (dir_config->auth_cookie_regexp->re_nsub + 1 != NUM_SUBS) ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "Invalid cookie name %s", cookie_name);
		dir_config->auth_cookie_regexp = NULL;
	}
	if ( dir_config->auth_cookie_regexp ) {
		dir_config->auth_cookie_name = apr_pstrdup(dir_config->auth_cookie_pool, saved_cookie_name);
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "Regular expression could not be compiled.");
	}
}

static void set_auth_cookie_domain(iam_authn_dir_config_rec* dir_config, const char *domain)
{
	if ( strlen(domain) == 0 ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "CookieDomain values may not be null");
	}
	if ( domain[0] !=  '.' ) {
		if ( !is_valid_ip4(domain) ) {
			ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, NULL, "CookieDomain must be ip address or begin with a dot");
		}
	}
	if ( ap_strchr_c(&domain[1], '.') == NULL ) {
		ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, NULL, "CookieDomain values must contain at least one embedded dot");
	}
	dir_config->auth_cookie_domain = domain;
}


static const char *set_login_url(cmd_parms *parms, void *cfg, const char *arg1, const char* arg2, const char* arg3)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	dir_config->login_url      = arg1;
	dir_config->ui_server_name = arg3;
	dir_config->postback_param = apr_pstrcat(parms->pool, "?", arg2, "=", NULL);
	return cmd_set_noauth_uri_with_backend(NULL, cfg, dir_config->login_url, NULL);
}

static const char *set_logout_url(cmd_parms *parms, void *cfg, const char *arg1, const char* arg2)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	dir_config->logout_url      = arg1;
	dir_config->ui_server_name  = arg2;
	return cmd_set_noauth_uri_with_backend(NULL, cfg, dir_config->logout_url, NULL);
}

static const char *set_logout_redirect(cmd_parms *parms, void *cfg, const char *on_logout, const char *app_link, const char *internal_link)
{
	iam_authn_dir_config_rec *dir_config = (iam_authn_dir_config_rec*)cfg;
	dir_config->on_logout_redirect  = on_logout;
	dir_config->internal_leave_link = internal_link;
	dir_config->app_link_for_logout_redirect = app_link;
	return NULL;
}

static const char *set_redirect_overwrite(cmd_parms *parms, void *cfg, const char *arg1)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->redirect_overwrite  = arg1;
	return NULL;
}

static const char *set_proxypass_reverse(cmd_parms *parms, void *cfg, const char *arg1)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(parms->server->module_config, &iam_authn_module);
	server_config->proxypass_reverse  = arg1;
	return NULL;
}


static void *iam_authn_create_server_config(apr_pool_t *pool, server_rec *server)
{
	iam_authn_server_config_rec *server_config = apr_pcalloc(pool, sizeof(iam_authn_server_config_rec));
	/* default NULLs and zeroes should be set by apr_pcalloc */

	server_config->login_redirects = apr_array_make(pool,  8, sizeof(redirect_rec));

	/* {{{ defaults */

	server_config->tokens_expiration_time = apr_time_from_sec(5*30);
	server_config->esb_expiration_time    = apr_time_from_sec(5*60);
	server_config->noauth_expiration_time = apr_time_from_sec(15*60);

#ifdef SHARED_CACHE

	/* enable shared cache by default */
	server_config->shared_esb_caching = 0;
	server_config->shared_global_size = 64*1024;
	server_config->shared_size        = 64*1024;
	server_config->shared_sync_time   = 1;
	server_config->shared_cleanup     = 0;

#endif
	/* }}} end of defaults */

	return server_config;
}

static void *iam_authn_merge_server_config(apr_pool_t *pool, void* base, void* new)
{
	iam_authn_server_config_rec *merged = apr_pcalloc(pool, sizeof(iam_authn_server_config_rec));
	iam_authn_server_config_rec *parent = (iam_authn_server_config_rec*)base;
	iam_authn_server_config_rec *child  = (iam_authn_server_config_rec*)new;
	iam_authn_server_config_rec *from = NULL;
	if ( child ) {
		from = child;
	} else {
		from = parent;
	}
#ifdef MEMCACHE_CACHE
	if ( child && child->memcache_host ) {
		from = child;
	} else {
		from = parent;
	}
	merged->memcache_esb_caching = from->memcache_esb_caching;
	merged->memcache_host = from->memcache_host;
	merged->memcache_port = from->memcache_port;
	merged->memcache_handle = from->memcache_handle;
	merged->memcache_server = from->memcache_server;
#endif

#ifdef SHARED_CACHE
	if ( child && child->shared_esb_caching ) {
		from = child;
	} else {
		from = parent;
	}

	merged->shared_esb_caching = from->shared_esb_caching;

	merged->shared_global_size = from->shared_global_size;
	merged->shared_size        = from->shared_size;
	merged->shared_sync_time   = from->shared_sync_time;
	merged->shared_cleanup     = from->shared_cleanup;
#endif
	merged->is_dump_caching   = from->is_dump_caching;

	merged->tokens_expiration_time = from->tokens_expiration_time;
	merged->noauth_expiration_time = from->noauth_expiration_time;
	merged->esb_expiration_time    = from->esb_expiration_time;

	if ( child && child->redirect_overwrite ) {
		from = child;
	} else {
		from = parent;
	}
	merged->redirect_overwrite = from->redirect_overwrite;

	if ( child && child->proxypass_reverse ) {
		from = child;
	} else {
		from = parent;
	}
	merged->proxypass_reverse = from->proxypass_reverse;

	if ( child && child->login_redirects ) {
		from = child;
	} else {
		from = parent;
	}
	merged->login_redirects = apr_array_make(pool,  from->login_redirects->nelts, sizeof(redirect_rec));
	int i = 0;
	for( i = 0; i < from->login_redirects->nelts; ++i) {
		redirect_rec *item = ((redirect_rec*)(from->login_redirects->elts)) + i;
		redirect_rec* new_item = (redirect_rec*)apr_array_push(merged->login_redirects);
		new_item->from = item->from;
		new_item->to   = item->to;
	}

	return merged;
}

static void *iam_authn_create_dir_config(apr_pool_t *pool, char *d)
{
	iam_authn_dir_config_rec *dir_config = apr_pcalloc(pool, sizeof(*dir_config));
	dir_config->path            = d;

	dir_config->noauth_uri_list     = apr_array_make(pool, 24, sizeof(map_rec));
	dir_config->noauth_prefix_list  = apr_array_make(pool,  8, sizeof(map_rec));
	dir_config->noauth_suffix_list  = apr_array_make(pool,  8, sizeof(map_rec));

	dir_config->exclude_uri_list     = apr_array_make(pool,  8, sizeof(map_rec));
	dir_config->exclude_prefix_list  = apr_array_make(pool,  8, sizeof(map_rec));

	dir_config->simple_cache_uri_list = apr_array_make(pool, 16, sizeof(map_rec));

	dir_config->viewstate_urls_list    = apr_array_make(pool,  8, sizeof(map_rec));
	dir_config->unset_allcookies_list  = apr_array_make(pool,  8, sizeof(map_rec));

	dir_config->redirects       = apr_array_make(pool,  8, sizeof(redirect_rec));
	dir_config->redirects_before_auth = apr_array_make(pool,  8, sizeof(redirect_rec));
	dir_config->patterns        = apr_array_make(pool,  8, sizeof(subst_pattern_t));
	dir_config->target_servers  = apr_array_make(pool,  8, sizeof(map_rec));
	dir_config->form_post_paths = apr_array_make(pool,  2, sizeof(const char*));
	dir_config->generate_form_post_paths = apr_array_make(pool,  2, sizeof(const char*));

	dir_config->multipart_urls  = apr_table_make(pool, 10);
	dir_config->expired_headers = apr_table_make(pool, 10);
	dir_config->missing_auth_headers = apr_table_make(pool, 10);
	dir_config->logout_headers = apr_table_make(pool, 10);
	dir_config->skip_form_post_if_cookie_present = apr_table_make(pool, 10);

	/* {{{ defaults */
	dir_config->is_send_scheme   = 1;

	dir_config->service_auth           = ESB_SERVICE_AUTH;
	dir_config->service_key_management = ESB_KEY_MANAGEMENT;
	dir_config->service_federation     = ESB_FEDERATION;
	dir_config->service_cert           = ESB_CERT;

	/* new cookies processing */
	dir_config->max_time_difference    = 300000; /* 5 min */

	/* Kerberos config */
	dir_config->krb_verify_kdc    = 1;
	/* end of Kerberos config */

	dir_config->do_not_generate_cookie_for_cert_auth = 1;
	dir_config->read_client_cert_from_header = 1;
	dir_config->client_cert_header_name = s_client_cert_header;

	dir_config->viewstate_follow_location = 1;

	/* }}} end of defaults */

	return dir_config;
}

static const char* extract_server_from_url(apr_pool_t *pool, const char* url, int extract_scheme, char** uri)
{
	char*       end;
	int         length;
	const char* start = url;
	const char* s;

	s = strstr(url, "//");
	if ( s ) {
		s = s + 2; /* skip "//" */
	}
	if ( !extract_scheme ) {
		if ( s ) {
			start = s;
		}
	}
	end = strchr(s, '/');
	if ( end ) {
		if ( uri ) {
			*uri = end;
		}
		length = end - start + 1;
		if ( extract_scheme ) {
			length ++;
		}
		if ( length > 0 ) {
			char* header = apr_palloc(pool, length);
			apr_cpystrn(header, start, length);
			return header;
		}
	} else {
		if ( uri ) {
			*uri = apr_pstrdup(pool, "/");
		}
		return apr_pstrdup(pool, start);
	}
	return NULL;
}


/* functions */

static void set_expired_headers(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set_expired_headers()");
	}

	const apr_array_header_t *tarr = apr_table_elts(dir_config->expired_headers);
	const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
	int i;

	for (i = 0; i < tarr->nelts; i++) {
		apr_table_add(r->err_headers_out, telts[i].key, telts[i].val);
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set expiration headers: %s %s", telts[i].key, telts[i].val);
		}
	}
}

static void set_missing_auth_headers(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set_missing_auth_headers()");
	}

	const apr_array_header_t *tarr = apr_table_elts(dir_config->missing_auth_headers);
	const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
	int i;

	for (i = 0; i < tarr->nelts; i++) {
		apr_table_add(r->err_headers_out, telts[i].key, telts[i].val);
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set missing auth headers: %s %s", telts[i].key, telts[i].val);
		}
	}
}

static void set_logout_headers(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set_logout_headers(");
	}

	const apr_array_header_t *tarr = apr_table_elts(dir_config->logout_headers);
	const apr_table_entry_t *telts = (const apr_table_entry_t*)tarr->elts;
	int i;

	for (i = 0; i < tarr->nelts; i++) {
		apr_table_add(r->err_headers_out, telts[i].key, telts[i].val);
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set logout headers: %s %s", telts[i].key, telts[i].val);
		}
	}
}


static iam_authn_request_config_rec *iam_authn_get_request_config(request_rec *r)
{
	iam_authn_request_config_rec *request_config = ap_get_module_config(r->request_config, &iam_authn_module);
	if ( request_config == NULL ) {
		request_config = apr_pcalloc(r->pool, sizeof(*request_config));
		ap_set_module_config(r->request_config, &iam_authn_module, request_config);
	}
	return request_config;
}

static CURL* get_curl_session(request_rec* r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->curl_session ) {
		//curl_easy_reset( dir_config->curl_session );
	} else {
		/* curl_global_init() MUST be already called to avoid multithreaded errors */
		dir_config->curl_session = curl_easy_init();
		if ( dir_config->curl_session ) {
			apr_pool_cleanup_register(r->server->process->pool, dir_config->curl_session, (void *)curl_easy_cleanup, apr_pool_cleanup_null);
			curl_easy_setopt(dir_config->curl_session, CURLOPT_NOSIGNAL, TRUE);

			curl_easy_setopt(dir_config->curl_session, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

			/* avoid SSL segfault */ 
			curl_easy_setopt(dir_config->curl_session, CURLOPT_SSL_VERIFYHOST, 0);
			curl_easy_setopt(dir_config->curl_session, CURLOPT_SSL_VERIFYPEER, 0);

	/* try to keep connectoin open */
#ifdef CURLOPT_TCP_KEEPALIVE
			if ( curl_easy_setopt(dir_config->curl_session, CURLOPT_TCP_KEEPALIVE, 1) == CURLE_OK ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL keep-alive enabled");
			}
#endif

			struct curl_slist *headers = NULL;
			//headers = curl_slist_append(headers, "Connection: Keep-Alive");
			headers = curl_slist_append(headers, "Content-Type: text/plain");

			if ( headers ) {
				apr_pool_cleanup_register(r->server->process->pool, headers, (void *) curl_slist_free_all, apr_pool_cleanup_null);
				curl_easy_setopt(dir_config->curl_session, CURLOPT_HTTPHEADER, headers);
			}

		}
	}
	if ( dir_config->curl_session == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, "Can't init curl");
		return NULL;
	}
	return dir_config->curl_session;
}


static CURL* get_curl_fetch_session(request_rec* r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->curl_fetch_session ) {
		curl_easy_reset( dir_config->curl_fetch_session );
	} else {
		/* curl_global_init() MUST be already called to avoid multithreaded errors */
		dir_config->curl_fetch_session = curl_easy_init();
		if ( dir_config->curl_fetch_session ) {
			apr_pool_cleanup_register(r->server->process->pool, dir_config->curl_fetch_session, (void *)curl_easy_cleanup, apr_pool_cleanup_null);
			curl_easy_setopt(dir_config->curl_fetch_session, CURLOPT_NOSIGNAL, TRUE);
			curl_easy_setopt(dir_config->curl_fetch_session, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

			/* avoid SSL segfault */ 
			curl_easy_setopt(dir_config->curl_fetch_session, CURLOPT_SSL_VERIFYHOST, 0);
			curl_easy_setopt(dir_config->curl_fetch_session, CURLOPT_SSL_VERIFYPEER, 0);

	/* try to keep connectoin open */
#ifdef CURLOPT_TCP_KEEPALIVE
			if ( curl_easy_setopt(dir_config->curl_fetch_session, CURLOPT_TCP_KEEPALIVE, 1) == CURLE_OK ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL keep-alive enabled");
			}
#endif

		}
	}
	if ( dir_config->curl_fetch_session == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, r->server, "Can't init curl");
		return NULL;
	}
	return dir_config->curl_fetch_session;
}

static apr_status_t set_curl_params_xml(request_rec *r, CURL* curl, curl_recv_context_rec *curl_recv_context,
				xmlNodePtr xml_node_soap_command, const char *service_name)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	xmlChar *xml_request_buffer = NULL;
	int xml_request_buffer_size = 0;
	/* xml without formatting works faster in libxml */
	xmlDocDumpFormatMemory(xml_node_soap_command->doc, &xml_request_buffer, &xml_request_buffer_size, 0);
	if ( xml_request_buffer == NULL || xml_request_buffer_size == 0 ) {
		return 1;
	} else {
		if ( dir_config->is_verbose && dir_config->is_dump_curl) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL SEND: %s", xml_request_buffer);
		}
		apr_pool_cleanup_register(r->pool, xml_request_buffer, (void *) xmlFree, apr_pool_cleanup_null);
	}
	char* remote_url = apr_pstrcat(r->pool, dir_config->esb_server_name, service_name, NULL);
	curl_easy_setopt(curl, CURLOPT_URL, remote_url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_recv_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA,     curl_recv_context);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void *) xml_request_buffer);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, xml_request_buffer_size);

	return APR_SUCCESS;
}

/* Support for aspx __EVENTVALIDATION __VIEWSTATE */

static apr_status_t read_html_page_at_url(request_rec *r, const char* url, char** html_page)
{
	curl_recv_context_rec *curl_context = apr_pcalloc(r->pool, sizeof(*curl_context));
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	curl_context->pool = r->pool;
	CURL *curl = get_curl_fetch_session(r);
	if ( curl == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init curl session for request");
		return IAM_CURL_ERROR;
	}
	curl_easy_setopt(curl, CURLOPT_URL,           url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_recv_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA,     curl_context);

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1");
	curl_easy_setopt(curl, CURLOPT_REFERER,   url);
	if ( dir_config->viewstate_follow_location ) {
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, TRUE);
	} else {
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, FALSE);
	}

	/* avoid SSL segfault */ 
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, TRUE);

	long curl_http_code = 0;
	CURLcode curl_result_code = curl_easy_perform(curl);

	if ( curl_result_code != CURLE_OK ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "The curl request returned code %i", curl_result_code);
		return IAM_CURL_ERROR;
	}

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_http_code);

	if ( curl_http_code >= 300 && curl_http_code < 400 ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "curl warning while get html page http code: %ld at %s", curl_http_code, url);
	}
	if ( curl_http_code >= 400 ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "curl can't get html page http error: %ld at %s", curl_http_code, url);
		return IAM_CURL_ERROR;
	}

	if ( curl_context->response_data == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "empty buffer then trying to get page at %s", url);
		return IAM_CURL_ERROR;
	}

	*html_page = curl_context->response_data;

	return APR_SUCCESS;
}

static xmlDocPtr parse_xml_content(apr_pool_t *pool, const char *xml_content)
{
	if ( xml_content == NULL ) {
		return NULL;
	}
	xmlDocPtr result = xmlParseMemory(xml_content, strlen(xml_content));
	if ( result == NULL ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to parse OpenIAM service soap response");
		return NULL;
	}

	apr_pool_cleanup_register(pool, result, (void *) xmlFreeDoc, apr_pool_cleanup_null);
	return result;
}

static char* request_api_command_xml(request_rec *r, xmlNodePtr xml_node_soap_command, const char *service_name)
{
	CURLcode curl_result_code;
	long curl_http_code = 0;
	curl_recv_context_rec *curl_context = apr_pcalloc(r->pool, sizeof(*curl_context));
	curl_context->pool = r->pool;
	CURL *curl = get_curl_session(r);
	if ( curl == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init curl session for request");
		return NULL;
	}
	if ( set_curl_params_xml(r, curl, curl_context, xml_node_soap_command, service_name) != APR_SUCCESS ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't set curl params");
		return NULL;
	}
	curl_result_code = curl_easy_perform(curl);
	if ( curl_result_code == CURLE_OK ) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_http_code);
		if ( curl_http_code != 200 ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OpenIAM service returned code %u", (unsigned int) curl_http_code);
			return NULL;
		}
		iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
		if ( dir_config->is_verbose && dir_config->is_dump_curl ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL RETURNS: (%i) %s", curl_result_code, curl_context->response_data);
		}
		return curl_context->response_data;
	}

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "The curl request returned code %i", curl_result_code);
	return NULL;
}

apr_status_t process_uri_authlist_xml(apr_pool_t *pool, request_rec *r, xmlDocPtr xml_doc, char** error_str)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	int i;
	xmlNodeSetPtr xml_auth_nodes = find_nodes_xml(pool, xml_doc, "//authLevelTokenList", error_str);
	if ( dir_config->is_debug_filters ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "process_uri_authlist_xml" );
	}
	if ( xml_auth_nodes ) {
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "process_uri_authlist_xml size = %d", xml_auth_nodes->nodeNr);
		}
		for ( i = 0; i < xml_auth_nodes->nodeNr; ++i ) {
			xmlNodePtr xml_auth_item = xml_auth_nodes->nodeTab[i];
			if ( xml_auth_item ) {
				if ( dir_config->is_debug_filters ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "xml_auth_item = %s", xml_auth_item->name);
				}
				if ( strcmp((char*)xml_auth_item->name, "authLevelTokenList") == 0 ) {
					xmlNodePtr subchild = xml_auth_item->children;
					while ( subchild ) {
						if ( dir_config->is_debug_filters ) {
							ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "subchild = %s", subchild->name);
						}
						if ( subchild && subchild->name && strcmp((const char*)subchild->name, "authLevelId") == 0 ) {
							char* authId = (char*)xmlNodeGetContent(subchild);
							if ( dir_config->is_debug_filters ) {
								ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "authId = %s", authId);
							}
							iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);

							if ( strcmp(authId, "NONE") == 0 ) {
								request_config->no_auth = 1;
							} else if ( strcmp(authId, "PASSWORD_AUTH") == 0 ) {
								request_config->password_auth = 1;
							} else if ( strcmp(authId, "CERT_AUTH") == 0 ) {
								request_config->cert_auth = 1;
							} else if ( strcmp(authId, "KERB_AUTH") == 0 ) {
								request_config->kerb_auth = 1;
							}
						}
						subchild = subchild->next;
					}
				}
			}
		}
	}
	return APR_SUCCESS;
}

static apr_status_t set_curl_params_rest(request_rec *r, CURL* curl, curl_recv_context_rec *curl_recv_context, const char* url, const char* name, const char* content)
{
	//iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	const char* boundary= OPENIAM_DEFAULT_BOUNDIARY;// "OPENIAM0123456789ABCDEFGHIJKLMNOPQRSTadfjkqrew789afsdj";
	char* header = apr_pstrcat(r->pool, "Content-Type: multipart/form-data; boundary=", boundary, NULL);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, header);

	if ( headers )
	{
		apr_pool_cleanup_register(r->server->process->pool, headers, (void *) curl_slist_free_all, apr_pool_cleanup_null);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	}

	char* data = apr_pstrcat(r->pool,
		"--", boundary,
		"\r\nContent-Disposition: form-data; name=\"", name, "\"; filename=\"rsacert.pem\"",
		"\r\nContent-Type: application/octet-stream\r\n\r\n",
		content,
		"\r\n--", boundary, "--", NULL);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_recv_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA,     curl_recv_context);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void *) data);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data));

	return APR_SUCCESS;
}


static char* request_api_command_rest(request_rec *r, const char* url, const char *content)
{
	CURLcode curl_result_code;
	long curl_http_code = 0;
	curl_recv_context_rec *curl_context = apr_pcalloc(r->pool, sizeof(*curl_context));
	curl_context->pool = r->pool;
	CURL *curl = get_curl_session(r);
	if ( curl == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init curl session for request");
		return NULL;
	}
	if ( set_curl_params_rest(r, curl, curl_context, url, "cert", content) != APR_SUCCESS )
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't set curl params");
		return NULL;
	}
	curl_result_code = curl_easy_perform(curl);
	if ( curl_result_code == CURLE_OK )
	{
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &curl_http_code);
		if ( curl_http_code != 200 )
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OpenIAM service returned code %u", (unsigned int) curl_http_code);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL RETURNS: (%i) %s", curl_result_code, curl_context->response_data ? curl_context->response_data : "(null)");
			return NULL;
		}
		iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
		if ( dir_config->is_verbose && dir_config->is_dump_curl )
		{
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "CURL RETURNS: (%i) %s", curl_result_code, curl_context->response_data);
		}
		return curl_context->response_data;
	}

	ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "The curl request returned code %i", curl_result_code);
	return NULL;
}

static map_rec* search_array(apr_array_header_t* arr, const char* uri)
{
	if (uri == NULL || arr->elts == NULL || arr->nelts == 0) {
		return NULL;
	}
	map_rec *item = (map_rec *)arr->elts;
	size_t length = strlen(uri);
	int i;

	for(i = 0; i < arr->nelts; ++i, item++) {
		if ( length == item->pattern_length ) {
			if ( strcasecmp(uri, item->pattern) == 0 ) {
				return item;
			}
		}
	}
	return NULL;
}

/* check for skip under construction resources */

static int skip_under_construction(request_rec *r)
{
	char *extention = strrchr(r->uri, '.');
	if ( extention == NULL ) {
		return 0;
	}

	if ( strcasecmp(extention, ".jpg") == 0 ||
	    strcasecmp(extention, ".jpeg") == 0 ||
	    strcasecmp(extention, ".png") == 0 ||
	    strcasecmp(extention, ".css") == 0 ) {
		return 1;
	}

	return 0;
}

static map_rec* search_array_prefix(apr_array_header_t* arr, const char* uri)
{
	if (uri == NULL || arr->elts == NULL || arr->nelts == 0) {
		return NULL;
	}
	map_rec *item = (map_rec *)arr->elts;
	size_t length = strlen(uri);
	int i;

	for( i = 0; i < arr->nelts; ++i, item++) {
		if ( length >= item->pattern_length ) {
			if ( strncasecmp(uri, item->pattern, item->pattern_length) == 0 ) {
				return item;
			}
		}
	}
	return NULL;
}

static map_rec* search_array_suffix(apr_array_header_t* arr, const char* uri)
{
	if (uri == NULL || arr->elts == NULL || arr->nelts == 0) {
		return NULL;
	}
	map_rec *item = (map_rec *)arr->elts;
	size_t length = strlen(uri);
	int i;

	for( i = 0; i < arr->nelts; ++i, item++) {
		if ( length >= item->pattern_length ) {
			size_t offset = length - item->pattern_length;
			if ( strncasecmp(uri + offset, item->pattern, item->pattern_length) == 0 ) {
				return item;
			}
		}
	}
	return NULL;
}

static map_rec* is_excluded_from_auth(request_rec *r)
{
	map_rec* result = NULL;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( (result = search_array_prefix(dir_config->noauth_prefix_list, r->uri)) ) {
		return result;
	}
	if ( (result = search_array_suffix(dir_config->noauth_suffix_list, r->uri)) ) {
		return result;
	}
	if ( (result = search_array(dir_config->noauth_uri_list, r->uri)) ) {
		return result;
	}

	return NULL;
}


static int is_excluded(request_rec *r)
{
	map_rec* result = NULL;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( (result = search_array_prefix(dir_config->exclude_prefix_list, r->uri)) ) {
		return 1;
	}
	if ( (result = search_array(dir_config->exclude_uri_list, r->uri)) ) {
		return 1;
	}

	return 0;
}

static const char* is_redirected(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	int i = 0;

	if ( r->uri && dir_config->redirects && dir_config->redirects->nelts > 0 ) {
		for( i = 0; i < dir_config->redirects->nelts; ++i) {
			redirect_rec *item = ((redirect_rec*)(dir_config->redirects->elts))+i;
			int compare = strcasecmp(r->uri, item->from);
			if ( compare == 0 ) {
				return item->to;
			}
		}
	}
	return NULL;
}

static const char* is_redirected_before_auth(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	int i = 0;

	if ( r->uri && dir_config->redirects_before_auth && dir_config->redirects_before_auth->nelts > 0 ) {
		for( i = 0; i < dir_config->redirects_before_auth->nelts; ++i) {
			redirect_rec *item = ((redirect_rec*)(dir_config->redirects_before_auth->elts))+i;
			int compare = strcasecmp(r->uri, item->from);
			if ( compare == 0 ) {
				return item->to;
			}
		}
	}
	return NULL;
}

static const char* login_redirect(request_rec *r)
{
	iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);

	int i = 0;
	if ( r->uri && server_config->login_redirects && server_config->login_redirects->nelts > 0 ) {
		for( i = 0; i < server_config->login_redirects->nelts; ++i) {
			redirect_rec *item = ((redirect_rec*)(server_config->login_redirects->elts))+i;
			int compare = strcasecmp(r->uri, item->from);
			if ( compare == 0 ) {
				return item->to;
			}
		}
	}

	if ( server_config->redirect_overwrite )
		return server_config->redirect_overwrite;

	if ( server_config->proxypass_reverse )
		return server_config->proxypass_reverse;

	return NULL;
}

static char* get_target_server_override(request_rec *r)
{
	map_rec* result = NULL;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	char *server_url = NULL;
	if ( (result = search_array_prefix(dir_config->target_servers, r->unparsed_uri)) ) {
		server_url = (char*)result->backend;
		if ( (strcasecmp(server_url, "localhost") == 0) || 
		     (strcasecmp(server_url, "http://localhost") == 0) || 
		     (strcasecmp(server_url, "http://localhost/") == 0)) {
			return "localhost";
		}
		return server_url;
	}

	return NULL;
}

static const char* viewstate_url(request_rec *r)
{
	map_rec* result = NULL;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( (result = search_array_prefix(dir_config->viewstate_urls_list, r->unparsed_uri)) ) {
		return result->backend;
	}

	return NULL;
}

static int is_unset_allcookies(request_rec *r)
{
	map_rec* result = NULL;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( (result = search_array_prefix(dir_config->unset_allcookies_list, r->unparsed_uri)) ) {
		return 1;
	}

	return 0;
}


apr_status_t process_uri_pattern(void* p, int pattern_type, apr_array_header_t* values)
{
	request_rec* r = (request_rec*)p;

	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	int length = 0;

	int is_form_posts_list_configured = dir_config->form_post_paths &&
	                                    dir_config->form_post_paths->nelts;
	int is_generate_form_posts_list_configured = dir_config->generate_form_post_paths &&
	                                             dir_config->generate_form_post_paths->nelts;


	const char* viewstate_url_source = viewstate_url(r);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "viewstate_url = %s (follow_location=%d)", viewstate_url_source, dir_config->viewstate_follow_location);
	}
	if ( viewstate_url_source ) {
		char *html_page_buff = NULL;
		if ( read_html_page_at_url(r, viewstate_url_source, &html_page_buff) != APR_SUCCESS ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "can't get __VIEWSTATE and __EVENTVALIDATION codes");
			}
		} else {
			if ( html_page_buff ) {
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "read_html_page_at_url success");
				}
				if ( dir_config->viewstate_str ) {
					char saved = ' ';
					const char *viewstate       = strstr(html_page_buff, "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=\"");
					char *viewstate_end         = NULL;
					if ( viewstate && dir_config->viewstate_str) {
						viewstate += 64; // strlen()
						viewstate_end     = strstr(viewstate, "\" />");
						if ( viewstate_end ) {
							saved = *viewstate_end;
							*viewstate_end = '\0';
						} else {
							viewstate = NULL;
						}
						if ( dir_config->is_verbose ) {
							ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "__VIEWSTATE %s", viewstate);
						}
						replace_placeholders(r->pool, values, dir_config->viewstate_str, apr_pstrdup(r->pool, viewstate));
						if ( viewstate_end ) {
							*viewstate_end = saved;
						}
					}
				}
				if ( dir_config->viewstategenerator_str ) {
					char saved = ' ';
					const char *viewstategenerator       = strstr(html_page_buff, "<input type=\"hidden\" name=\"__VIEWSTATEGENERATOR\" id=\"__VIEWSTATEGENERATOR\" value=\"");
					char *viewstategenerator_end         = NULL;
					if ( viewstategenerator && dir_config->viewstategenerator_str) {
						viewstategenerator += strlen("<input type=\"hidden\" name=\"__VIEWSTATEGENERATOR\" id=\"__VIEWSTATEGENERATOR\" value=\"");
						viewstategenerator_end     = strstr(viewstategenerator, "\" />");
						if ( viewstategenerator_end ) {
							saved = *viewstategenerator_end;
							*viewstategenerator_end = '\0';
						} else {
							viewstategenerator = NULL;
						}
						if ( dir_config->is_verbose ) {
							ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "__VIEWSTATEGENERATOR %s", viewstategenerator);
						}
						replace_placeholders(r->pool, values, dir_config->viewstategenerator_str, apr_pstrdup(r->pool, viewstategenerator));
						if ( viewstategenerator_end ) {
							*viewstategenerator_end = saved;
						}
					}
				}
				if ( dir_config->eventvalidation_str ) {
					char saved = ' ';
					const char *eventvalidation = strstr(html_page_buff, "<input type=\"hidden\" name=\"__EVENTVALIDATION\" id=\"__EVENTVALIDATION\" value=\"");
					char *eventvalidation_end   = NULL;
					if ( eventvalidation ) {
						eventvalidation += strlen("<input type=\"hidden\" name=\"__EVENTVALIDATION\" id=\"__EVENTVALIDATION\" value=\"");
						eventvalidation_end = strstr(eventvalidation, "\" />");
						if ( eventvalidation_end ) {
							saved = *eventvalidation_end;
							*eventvalidation_end = '\0';
						} else {
							eventvalidation = NULL;
						}
						replace_placeholders(r->pool, values, dir_config->eventvalidation_str, apr_pstrdup(r->pool, eventvalidation));
						if ( eventvalidation_end ) {
							*eventvalidation_end = saved;
						}
					}
				}
				if ( dir_config->eventtarget_str ) {
					char saved = ' ';
					const char *eventtarget = strstr(html_page_buff, "<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"");
					char *eventtarget_end   = NULL;
					if ( eventtarget ) {
						eventtarget += strlen("<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"");
						eventtarget_end = strstr(eventtarget, "\" />");
						if ( eventtarget_end ) {
							saved = *eventtarget_end;
							*eventtarget_end = '\0';
						} else {
							eventtarget = NULL;
						}
						replace_placeholders(r->pool, values, dir_config->eventtarget_str, apr_pstrdup(r->pool, eventtarget));
						if ( eventtarget_end ) {
							*eventtarget_end = saved;
						}
					}
				}
				if ( dir_config->eventargument_str ) {
					char saved = ' ';
					const char *eventargument = strstr(html_page_buff, "<input type=\"hidden\" name=\"__EVENTARGUMENT\" id=\"__EVENTARGUMENT\" value=\"");
					char *eventargument_end   = NULL;
					if ( eventargument ) {
						eventargument += strlen("<input type=\"hidden\" name=\"__EVENTARGUMENT\" id=\"__EVENTARGUMENT\" value=\"");
						eventargument_end = strstr(eventargument, "\" />");
						if ( eventargument_end ) {
							saved = *eventargument_end;
							*eventargument_end = '\0';
						} else {
							eventargument = NULL;
						}
						replace_placeholders(r->pool, values, dir_config->eventargument_str, apr_pstrdup(r->pool, eventargument));
						if ( eventargument_end ) {
							*eventargument_end = saved;
						}
					}
				}

			} else {
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "can't get __VIEWSTATE and __EVENTVALIDATION codes from html at url: %s", viewstate_url_source);
				}
			}
		}
	}

	if ( dir_config->is_debug_filters ) {
		iam_debug_dump_array(r, values, "FIXED PATTERN VALUES:", "  ");
	}



	if ( pattern_type == URI_PATTERN_METATYPE_FORM ) {

		char *cookieval = NULL;
		const char *cookies = apr_table_get(r->headers_in, "Cookie");
		const char *cookie_name = apr_table_get(dir_config->skip_form_post_if_cookie_present, r->unparsed_uri);

		//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "cookie_name=%s", cookie_name);

		if ( cookie_name && cookies ) {

			int danger_chars = 0;
			const char *sp = cookie_name;
			const char* regexp_string;
			/* The goal is to end up with this regexp,
			 * ^cookie_name=([^;,]+)|[;,][ \t]+cookie_name=([^;,]+)
			 * with cookie_name obviously substituted either
			 * with the real cookie name set by the user in httpd.conf, or with the
			 * default COOKIE_NAME. */
			/* Anyway, we need to escape the cookie_name before pasting it
			 * into the regex
			 */
			while ( *sp ) {
				if ( !apr_isalnum(*sp) ) {
					++danger_chars;
				}
				++sp;
			}
			if ( danger_chars ) {
				char *cp;
				cp = apr_palloc(r->pool, sp - cookie_name + danger_chars + 1); /* 1 == \0 */
				sp = cookie_name;
				cookie_name = cp;
				while ( *sp ) {
					if ( !apr_isalnum(*sp) ) {
						*cp++ = '\\';
					}
					*cp++ = *sp++;
				}
				*cp = '\0';
			}
			//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "cookie_name=%s", cookie_name);
			regexp_string = apr_pstrcat(r->pool, "^", cookie_name, "=([^;,]+)|[;,][ \t]*", cookie_name, "=([^;,]+)", NULL);

			ap_regex_t* cookie_regexp = ap_pregcomp(r->pool, regexp_string, AP_REG_EXTENDED);
			if ( cookie_regexp ) {
				//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "regexp_string=%s", regexp_string);
				ap_regmatch_t regm[NUM_SUBS];
				if ( !ap_regexec(cookie_regexp, cookies, NUM_SUBS, regm, 0) ) {
					/* Our regexp,
					 * ^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)
					 * only allows for $1 or $2 to be available. ($0 is always
					 * filled with the entire matched expression, not just
					 * the part in parentheses.) So just check for either one
					 * and assign to cookieval if present. */
					if ( regm[1].rm_so != -1 ) {
						cookieval = ap_pregsub(r->pool, "$1", cookies, NUM_SUBS, regm);
					}
					if ( regm[2].rm_so != -1 ) {
						cookieval = ap_pregsub(r->pool, "$2", cookies, NUM_SUBS, regm);
					}
				}
			}
		}

		//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "cookieval=%s", cookieval);
		if ( cookieval ) {
			//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "skip FORM POST generation");
			return APR_SUCCESS;
		}

		//ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "FORM POST generation");
		if ( is_generate_form_posts_list_configured ) {
			int found = 0;
			int i;
			for ( i = 0; i < dir_config->generate_form_post_paths->nelts; ++i ) {
				const char* uri  = ((const char**)dir_config->generate_form_post_paths->elts)[i];
				if ( uri ) {
					if ( strcasecmp(r->unparsed_uri, uri) == 0) {
						found = 1;
						apr_table_setn(r->notes, NOTE_GENERATE_FORM_POST, "1");
						iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
						request_config->form_fields = values;
						iam_debug_dump_array(r, values, "FORM POST VALUES:", "      ");
						ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "OPENIAM_GenerateFormPostURI set for uri %s", r->unparsed_uri);
						break;
					}
				}
			}
		} else {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "generate form posts list not configured (no OPENIAM_GenerateFormPostURI commands in config). using ESB uri patterns.");
		}

		if ( is_form_posts_list_configured ) {
			if ( r->method_number == M_POST ) {
				//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "send login form post only on GET requests. POST requests can have parameters in body.");
				//return APR_SUCCESS;
			}
			int found = 0;
			int i;
			for ( i = 0; i < dir_config->form_post_paths->nelts; ++i ) {
				const char* uri  = ((const char**)dir_config->form_post_paths->elts)[i];
				if ( uri ) {
					if ( strcasecmp(r->unparsed_uri, uri) == 0) {
						found = 1;
						break;
					}
				}
			}
			if ( !found ) {
				return APR_SUCCESS;
			}
		} else {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "form posts list not configured (no OPENIAM_FormPostURI commands in config). using ESB uri patterns.");
		}


	}
	if ( dir_config->is_debug_filters ) {
		iam_debug_dump_array(r, values, "PATTERN VALUES:", "  ");
	}

	/* check that we need do redirect */
	if ( pattern_type == URI_PATTERN_METATYPE_HEADER ) {
		int i;
		for ( i = 0; i < values->nelts - 1; i += 3 ) {
			const char* name  = ((char**)values->elts)[i];
			const char* value = ((char**)values->elts)[i+1];
			if ( name && value ) {
				if ( strcasecmp(name, "OIAM_EULA_TEST_CH") == 0 ) {
					char* redirect_overwrite = (char*)login_redirect(r);
					char* value_url = (char*)value;
					if ( redirect_overwrite ) {
						value_url = apr_pstrcat(r->pool, redirect_overwrite, value, NULL);
					}
					if ( dir_config->is_verbose ) {
						ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "OIAM_EULA_TEST_CH = %s", value_url);
					}
					apr_table_setn(r->headers_out, "Location", value_url);
					return IAM_REDIRECTED;
				}
			}
		}
	}

	if ( pattern_type == URI_PATTERN_METATYPE_URI || pattern_type == URI_PATTERN_METATYPE_FORM ) {
		char *str_generate_form_post = apr_table_get(r->notes, NOTE_GENERATE_FORM_POST);
		if ( str_generate_form_post && strcmp(str_generate_form_post, "1") == 0 ) {
			// TODO: generate form post that will be posted from browser
		} else {
			const char *multipart_str = dir_config->multipart_str;
			if ( multipart_str == NULL ) {
				multipart_str = apr_table_get(dir_config->multipart_urls, r->uri);
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "multipart_str[%s]=%s", r->uri, multipart_str);
				}
			}
			char *args = ((pattern_type == URI_PATTERN_METATYPE_FORM) && multipart_str )
						? iam_multipart_str_from_key_value_pairs(r->pool, values, multipart_str)
						: iam_str_from_key_value_pairs(r->pool, values, '&', 0, 1);
			if ( dir_config->is_debug_filters ) {
				ap_log_error(APLOG_MARK, APLOG_WARNING, 0, r->server, "args=%s", args);
			}
			if ( args && (length = strlen(args)) ) {
				if ( pattern_type == URI_PATTERN_METATYPE_URI ) {
					if ( r->args ) {
						r->args = apr_pstrcat(r->pool, r->args, "&", args, NULL);
					} else {
						r->args = args;
					}
				} else {
					if ( multipart_str == NULL ) {
						r->content_type = "application/x-www-form-urlencoded";
					} else {
						r->content_type = apr_pstrcat(r->pool, "multipart/form-data; boundary=", multipart_str, NULL);
					}
					apr_table_setn(r->headers_in, "Content-Type", r->content_type);
					if ( r->method_number != M_POST ) {
						r->the_request   = apr_pstrcat(r->pool, "POST", r->the_request + strlen(r->method), NULL);
						r->method_number = M_POST;
						r->method        = "POST";
					}
					r->header_only = 0;
					/* Form POST body will be added in filter part of module */
					apr_table_setn(r->notes, NOTE_FORM_POST_DATA, args);
					ap_add_input_filter(s_post_form_filter_name, NULL, r, r->connection);
				}
			}
		}
	} else if ( pattern_type == URI_PATTERN_METATYPE_COOKIE ) {
		const char *cookies = iam_str_from_key_value_pairs(r->pool, values, ';', 0, 0);
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cookies= %s", cookies);
		}
		if ( cookies == NULL || strlen(cookies) == 0 ) {
			return APR_SUCCESS;
		}
		const char *cookie = apr_table_get(r->headers_in, "Cookie");
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cookie was %s", cookie);
		}
		if ( cookie == NULL ) {
			apr_table_setn(r->headers_in, "Cookie", cookies);
		} else {
			apr_table_setn(r->headers_in, "Cookie", apr_pstrcat(r->pool, cookie, ";", cookies, NULL));
		}
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cookie now %s", apr_table_get(r->headers_in, "Cookie"));
		}

		/* Also add in headers_out  */
		const char *out_cookies = iam_str_from_key_value_pairs(r->pool, values, ';', 1, 0);
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cookies to propagate= %s", out_cookies);
		}
		apr_table_setn(r->notes, NOTE_PROPAGATE_COOKIES, out_cookies);
	} else if ( pattern_type == URI_PATTERN_METATYPE_HEADER ) {
		int i;
		for ( i = 0; i < values->nelts - 1; i += 3 ) {
			const char* name  = ((char**)values->elts)[i];
			const char* value = ((char**)values->elts)[i+1];
			const char* propagate = ((char**)values->elts)[i+2];
			if ( name && value ) {
				if ( dir_config->is_debug_filters ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set headers in %s=%s", name, value);
				}
				apr_table_setn(r->headers_in, name, value);
				if ( propagate ) {
					apr_table_setn(r->headers_out, name, value);
				}
			}
		}
		const char *headers = iam_str_from_key_value_pairs_without_values(r->pool, values, ';', 1);
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "headers to propagate= %s", headers);
		}
		apr_table_setn(r->notes, NOTE_PROPAGATE_HEADERS, headers);
	}

	return APR_SUCCESS;
}

static void log_federation_error_code(request_rec *r, const char* error_code)
{
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Federation returns error: %s", error_code);
}

/* http://wiki.openiam.com/display/IAMENGINEERING/Cookie+Federation+via+UI+and+Proxy */
static apr_status_t api_federate_proxy_uri(request_rec *r, const char *user_id, const char *uri, const char *method, char **server_url)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	iam_authn_request_config_rec *request_config = ap_get_module_config(r->request_config, &iam_authn_module);
	iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);
	xmlNodePtr  xml_node_soap_command;
	xmlDocPtr   xml_soap_response;
	xmlNodePtr  xml_node_response_return;
	xmlNodePtr  xml_node_server_url;
	xmlChar    *xml_string_server_url;
	xmlNodePtr  xml_node_cp_id_url;
	xmlNodePtr  xml_node_pattern_id_url;

	int         is_failed;
	const char *error_code;
	const char *cp_id       = NULL;
	const char *pattern_id  = NULL;
	char       *error_str   = NULL;
	apr_status_t ret;

	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "federate proxy uri:%s, %s", user_id, uri);
	}

	xml_node_soap_command = create_api_command_xml(r->pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service", &error_str);
	if ( xml_node_soap_command == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "FEDERATE PROXY URI: create_api_command_xml error:%s", error_str);
		return IAM_XML_ERROR;
	}
	if ( user_id ) { // user_id can be NULL 
		xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "userId", BAD_CAST user_id);
	}
	if ( method ) { // method can be NULL for v3
		xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "method", BAD_CAST method);
	}
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "proxyURI", BAD_CAST uri);

	char *federation_xml_content = NULL;
	char *cache_key_name = NULL;
	int need_to_store_in_cache = 0;

	if ( 0
#ifdef SHARED_CACHE
		|| server_config->shared_esb_caching
#endif
#ifdef DB_CACHE
		|| server_config->db_esb_caching
#endif
#ifdef MEMCACHE_CACHE
		|| server_config->memcache_esb_caching
#endif
	     ) {
	        cache_key_name = (char*)uri;
		//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "simple cache. checking uri=%s", r->uri);
		map_rec *mr = search_array_prefix(dir_config->simple_cache_uri_list, r->uri);
		if ( mr ) {
			//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "processing simple cache");
			char *s = strstr(uri, "://");
			if ( s && *s ) {
				s += 3;
				if ( *s ) {
					s = strchr(s, '/');
					while ( (s[0] == '/') && s ) {
						s++;
					}
				}
			}
			if ( s && *s ) {
				char *e = strchr(s, '/');
				if ( e ) {
					apr_size_t count = e - s;
					char *simple_cache_key_name = apr_palloc(r->pool, count+1);
					memcpy(simple_cache_key_name, s, count);
					simple_cache_key_name[count] = '\0';
					//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "simple cache key name=%s",simple_cache_key_name);
					cache_key_name = simple_cache_key_name;
				}
			}
		}

		if ( user_id != NULL ) {
			cache_key_name = iam_pstrcat(r->pool, cache_key_name, "|", user_id, NULL);
		}
	}

#ifdef SHARED_CACHE
	if ( cache_key_name && (federation_xml_content == NULL) && server_config->shared_esb_caching ) {

		if ( server_config->sc == NULL ) {

			server_config->sc = openiam_shm_cache_init(
					r->server->process->pool, server_config->shared_size,
					server_config->shared_sync_time, server_config->is_dump_caching,
					server_config->shared_cleanup);
			if ( server_config->sc == NULL ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init shm cache");
			}
		}

		if ( server_config->sc ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "lookup key %s in shm cache", cache_key_name);
			}
			federation_xml_content = openiam_shm_cache_get(server_config->sc, cache_key_name, r->pool);
		}

		if ( federation_xml_content ) {
			apr_atomic_inc32(&server_config->shared_hit);
		} else {
			need_to_store_in_cache = 1;
			apr_atomic_inc32(&server_config->shared_miss);
		}

		if ( server_config->is_dump_caching ) {
			int hit  = apr_atomic_read32(&server_config->shared_hit);
			int miss = apr_atomic_read32(&server_config->shared_miss);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SHARED_CACHE(hit %u/ miss %u) key=%s server=%d", hit, miss, cache_key_name, getpid());

			if ( federation_xml_content ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SHARED_CACHE found cached federation response for user_id=%s and uri=%s", user_id, uri);
			} else {
				need_to_store_in_cache = 1;
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SHARED_CACHE can't find cached federation response for user_id=%s and uri=%s", user_id, uri);
			}
		}
	}
#endif


#ifdef DB_CACHE
	if ( cache_key_name && (federation_xml_content == NULL) && server_config->db_esb_caching ) {
		if ( server_config->is_dump_caching ) {
			int hit  = apr_atomic_read32(&server_config->db_hit);
			int miss = apr_atomic_read32(&server_config->db_miss);
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DB_CACHE(hit %u/ miss %u) key=%s server=%d", hit, miss, cache_key_name, getpid());
		}
		if ( server_config->db_env == NULL ) {
			server_config->db_env = openiam_db_init(r->server->process->pool, server_config->db_path, 0, server_config->db_mutex_count);
			if ( server_config->db_env == NULL ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init db cache");
			} else {
				ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "init db cache at %s", server_config->db_path);
			}
		}

		if ( user_id == NULL ) {
			if ( server_config->db_noauth == NULL ) {
				server_config->db_noauth = openiam_db_open(server_config->db_env, "noauth", server_config->db_sync_after_commit);
			}
			if ( server_config->db_noauth ) {
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "lookup key %s in noauth cache", cache_key_name);
				}
				federation_xml_content = openiam_cache_get(server_config->db_noauth, cache_key_name, r->pool);
			} else {
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "noauth db is null");
				}
			}

		} else {
			if ( server_config->db_esb == NULL ) {
				server_config->db_esb = openiam_db_open(server_config->db_env, "esb", server_config->db_sync_after_commit);
			}
			if ( server_config->db_esb ) {
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "lookup key %s in esb cache", cache_key_name);
				}
				federation_xml_content = openiam_cache_get(server_config->db_esb, cache_key_name, r->pool);
			} else {
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "esb db is null");
				}
			}
		}

		if ( dir_config->is_verbose ) {
			if ( federation_xml_content ) {
				apr_atomic_inc32(&server_config->db_hit);
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DB_CACHE found cached federation response for user_id=%s and uri=%s", user_id, uri);
				}
			} else {
				need_to_store_in_cache = 1;
				apr_atomic_inc32(&server_config->db_miss);
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "DB_CACHE can't find cached federation response for user_id=%s and uri=%s", user_id, uri);
				}
			}
		}
	}
#endif

	if ( cache_key_name && (federation_xml_content == NULL) ) {
#ifdef MEMCACHE_CACHE
		if ( server_config->memcache_esb_caching && server_config->memcache_handle == NULL ) {
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "Initializing memcache server at %s:%d", server_config->memcache_host, server_config->memcache_port);
			ret = openiam_memcache_init(r->server->process->pool, server_config->memcache_host, server_config->memcache_port, 
				&server_config->memcache_server, &server_config->memcache_handle);
			if ( ret != APR_SUCCESS ) {
				server_config->memcache_esb_caching = 0;
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init memcache");
			}
		}

		if ( server_config->memcache_esb_caching ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MEMCACHE(%u/%u)", server_config->memcache_hit, server_config->memcache_miss);
			}
			federation_xml_content = openiam_memcache_get(server_config->memcache_handle, cache_key_name, r->pool);
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "XML CONTENT=%s", federation_xml_content);
				if ( federation_xml_content ) {
					apr_atomic_inc32(&server_config->memcache_hit);
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MEMCACHE found cached federation response for user_id=%s and uri=%s", user_id, uri);
				} else {
					need_to_store_in_cache = 1;
					apr_atomic_inc32(&server_config->memcache_miss);
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MEMCACHE can't find cached federation response for user_id=%s and uri=%s", user_id, uri);
				}
			}
		}
#endif
	}

	if ( federation_xml_content == NULL ) {
		federation_xml_content = request_api_command_xml(r, xml_node_soap_command, dir_config->service_federation);
	}

	if ( federation_xml_content == NULL ) {
		return OPENIAM_DATA_ERROR;
	}

	xml_soap_response = parse_xml_content(r->pool, federation_xml_content);
	if ( xml_soap_response == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "ESB federation send_api_command returned NULL");
		return IAM_CURL_ERROR;
	}

	xml_node_response_return = find_node_xml(r->pool, xml_soap_response, "//return", &error_str);
	if ( xml_node_response_return == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No <return> element found. error:%s", error_str);
		return IAM_XML_ERROR;
	}
	is_failed = !response_status_xml(r->pool, xml_node_response_return, &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}

	process_uri_authlist_xml(r->pool, r, xml_soap_response, &error_str); // we need to check it 
	if ( request_config->no_auth ) {
		is_failed = 0;
	}

	/* ALWAYS send the following headers to the URL inside the <server> section of the response:
	   1) X-OPENIAM-URI-PATTERN-ID = corresponds to the <patternId> part of the response
	   2) X-OPENIAM-CP-ID = corresponds to the <cpId> part of the response */

	xml_node_cp_id_url = find_node_xml(r->pool, xml_soap_response, "//cpId", &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}
	if ( xml_node_cp_id_url ) {
		cp_id = (char*)xmlNodeGetContent(xml_node_cp_id_url);
		if ( cp_id ) {
			apr_pool_cleanup_register(r->pool, cp_id, (void *) xmlFree, apr_pool_cleanup_null);
		}
	} 
	xml_node_pattern_id_url = find_node_xml(r->pool, xml_soap_response, "//patternId", &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}
	if ( xml_node_pattern_id_url ) {
		pattern_id = (char*)xmlNodeGetContent(xml_node_pattern_id_url);
		if ( pattern_id ) {
			apr_pool_cleanup_register(r->pool, pattern_id, (void *) xmlFree, apr_pool_cleanup_null);
		}
	}

	if ( pattern_id ) {
		apr_table_setn(r->headers_in, s_pattern_id_header, pattern_id);
	} else {
		apr_table_unset(r->headers_in, s_pattern_id_header);
	}
	if ( cp_id ) {
		apr_table_setn(r->headers_in, s_cp_id_header,  cp_id);
	} else {
		apr_table_unset(r->headers_in, s_cp_id_header);
	}

	xml_node_server_url = find_node_xml(r->pool, xml_soap_response, "//serverURL", &error_str);
	if ( !xml_node_server_url || error_str ) {
		//ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No serverURL element found:%s", error_str);
		return IAM_XML_ERROR;
	}
	xml_string_server_url = xmlNodeGetContent(xml_node_server_url);
	if ( xml_string_server_url == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "serverURL element is empty");
		return IAM_XML_ERROR;
	}
	apr_pool_cleanup_register(r->pool, xml_string_server_url, (void *) xmlFree, apr_pool_cleanup_null);
	*server_url = (char*)xml_string_server_url;

	if ( *server_url == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "serverURL element not found");
		return IAM_XML_ERROR;
	}


	if ( dir_config->is_debug_filters ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "process_uri_patterns_xml");
	}
	ret = process_uri_patterns_xml(r->pool, r, xml_soap_response, &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}
	if ( ret != APR_SUCCESS ) {
		return ret;
	}

#if (DEBUG_DUMP_PATTERNS)
	if ( dir_config->is_dump_requests && !request_config->no_auth ) {
		iam_debug_dump_request(r, "DUMP AFTER PROCESS PATTERNS: ");
	}
#endif

	if ( is_failed ) {
		if ( dir_config->is_verbose && user_id ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "federate uri failed user_id:%s uri:%s", user_id, uri);
		}

		error_code = (const char*)xmlGetProp(xml_node_response_return, BAD_CAST "//errorCode");
		if ( error_code ) {
			log_federation_error_code(r, error_code);
		}
		return IAM_ESB_ERROR;
	}

	// finally store in cache if everything was successfull

	if ( cache_key_name  ) {

#ifdef SHARED_CACHE
		if ( need_to_store_in_cache && server_config->shared_esb_caching && federation_xml_content ) {
			apr_status_t ret = APR_SUCCESS;
			if ( federation_xml_content ) {
				if ( user_id == NULL ) {
					ret = openiam_shm_cache_set(server_config->sc, cache_key_name, federation_xml_content, apr_time_now() + server_config->noauth_expiration_time);
				} else {
					ret = openiam_shm_cache_set(server_config->sc, cache_key_name, federation_xml_content, apr_time_now() + server_config->esb_expiration_time);
				}
			}

			if ( server_config->is_dump_caching ) {
				if ( ret == APR_SUCCESS ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SHARED_CACHE store federation response for %s", cache_key_name);
				} else {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "SHARED_CACHE can't store federation response for %s", cache_key_name);
				}
			}
		}
#endif


#ifdef DB_CACHE
		if ( need_to_store_in_cache && server_config->db_esb_caching && federation_xml_content ) {
			apr_status_t ret = APR_SUCCESS;
			if ( federation_xml_content ) {
				if ( user_id == NULL ) {
					ret = openiam_cache_set(server_config->db_noauth, cache_key_name, federation_xml_content, server_config->noauth_expiration_time, r->pool, 0);
				} else {
					ret = openiam_cache_set(server_config->db_esb, cache_key_name, federation_xml_content, server_config->esb_expiration_time, r->pool, 0);
				}
			}

			if ( server_config->is_dump_caching ) {
				if ( ret == APR_SUCCESS ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DB_CACHE store federation response for %s", cache_key_name);
				} else {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DB_CACHE can't store federation response for %s", cache_key_name);
				}
			}
		}
#endif

#ifdef MEMCACHE_CACHE
		if ( need_to_store_in_cache && 
		     server_config->memcache_esb_caching &&
		     federation_xml_content ) {
			apr_status_t ret = APR_SUCCESS;
			if ( federation_xml_content ) {
				ret = openiam_memcache_set(server_config->memcache_handle, cache_key_name, federation_xml_content, apr_time_msec(server_config->esb_expiration_time), r->pool);
			}

			if ( dir_config->is_verbose ) {
				if ( ret == APR_SUCCESS ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MEMCACHE store federation response for %s", cache_key_name);
				} else {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "MEMCACHE can't store federation response for %s", cache_key_name);
				}
			}
		}
#endif

	}



	return ret;
}

/* https://openiam.atlassian.net/wiki/pages/viewpage.action?spaceKey=IAMENGINEERING&title=Certificate+Based+Authentication */
static apr_status_t api_send_cert_to_esb(request_rec *r, const char *pem, const char *uri, const char *method, char** output)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	//iam_authn_request_config_rec *request_config = ap_get_module_config(r->request_config, &iam_authn_module);
	//iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);

	const char *rest_url = apr_pstrcat(r->pool, dir_config->esb_server_name, dir_config->service_cert, 
		"?proxyURI=", iam_escape_uri(r->pool, ap_construct_url(r->pool, r->unparsed_uri, r)), "&method=", r->method, NULL);

	if ( dir_config->is_debug_cert ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Certificate Authentication: send pem certificate to esb url: %s", rest_url);
	}

	char* response = request_api_command_rest(r, rest_url, pem);

	if ( response == NULL )
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Certificate Authentication: sending pem error");
		return IAM_CURL_ERROR;
	}

	if ( dir_config->is_debug_cert ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "response: %s", response);
	}

	if ( output ) {
		*output = response;
	}

	return APR_SUCCESS;
}


static apr_status_t api_get_private_key(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	xmlNodePtr xml_node_soap_command      = NULL;
	xmlDocPtr  xml_soap_response          = NULL;
	xmlNodePtr xml_node_response_return   = NULL;
	char* error_str = NULL;

	const char* response_return;
	int len;
	unsigned char* decoded_key;

	if ( dir_config->evp_key == 0 ) { 
		xml_node_soap_command = create_api_command_xml(r->pool, "getCookieKey", "urn:idm.openiam.org/srvc/key/service", &error_str);
		if ( xml_node_soap_command == NULL || error_str ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: create_api_command_xml returned: %s", error_str);
			return IAM_XML_ERROR;
		}
		xml_soap_response = parse_xml_content(r->pool, request_api_command_xml(r, xml_node_soap_command, dir_config->service_key_management));
		if ( xml_soap_response == NULL ) {
			// fallback to 3.4 if response is NULL
			xml_node_soap_command = create_api_command_xml(r->pool, "getCookieKey", "urn:idm.openiam.org/srvc/res/service", &error_str);
			if ( xml_node_soap_command == NULL || error_str ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: create_api_command_xml returned: %s", error_str);
				return IAM_XML_ERROR;
			}
			xml_soap_response = parse_xml_content(r->pool, request_api_command_xml(r, xml_node_soap_command, dir_config->service_key_management));
			if ( xml_soap_response == NULL ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: send_api_command returned NULL");
				return IAM_CURL_ERROR;
			}
		}
		xml_node_response_return = find_node_xml(r->pool, xml_soap_response, "//return", &error_str);
		if ( xml_node_response_return == NULL || error_str ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: No <return> element found: %s", error_str);
			return IAM_XML_ERROR;
		}
		response_return = (char*)xmlNodeGetContent(xml_node_response_return);
		if ( response_return == NULL ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: element is empty");
			return IAM_XML_ERROR;
		}
		apr_pool_cleanup_register(r->pool, response_return, (void *) xmlFree, apr_pool_cleanup_null);
		len = apr_base64_decode_len(response_return);
		decoded_key = apr_pcalloc(r->server->process->pconf, len);
		len = apr_base64_decode((char*)decoded_key, response_return);

		if ( dir_config->is_debug_cookies ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: recieved key. length = %d", len);
		}

		dir_config->evp_key_length = len;
		dir_config->evp_key = decoded_key;
	} else {
		if ( dir_config->is_debug_cookies ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "GET PRIVATE KEY: key already obtained");
		}
	}
	return dir_config->evp_key ? APR_SUCCESS : IAM_CRYPTO_ERROR;
}

static apr_status_t api_renew_token_xml(
		request_rec* r, 
		char** principal,
		char** token,
		char** token_type,
		char** expiration_time,
		char** create_time,
		char** user_id)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( token == NULL ||
	     token_type == NULL ||
	     principal == NULL ) {
		return IAM_ERROR;
	}

	xmlNodePtr xml_node_soap_command      = NULL;
	xmlDocPtr  xml_soap_response          = NULL;
	xmlNodePtr xml_node_response_return   = NULL;
	char* error_str = NULL;
	xml_node_soap_command = create_api_command_xml(r->pool, "renewToken", "http://service.auth.srvc.idm.openiam.org/", &error_str);
	if ( xml_node_soap_command == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKEN AUTHENTICATION: create_api_command_xml returned: %s", error_str);
		return IAM_XML_ERROR;
	}
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "principal", BAD_CAST *principal);
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "token",     BAD_CAST *token);
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "tokenType", BAD_CAST *token_type);

	xml_soap_response = parse_xml_content(r->pool, request_api_command_xml(r, xml_node_soap_command, dir_config->service_auth));
	if ( xml_soap_response == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "api_renew_token_xml send_api_command_xml returned NULL");
		return IAM_CURL_ERROR;
	}
	xml_node_response_return = find_node_xml(r->pool, xml_soap_response, "//return", &error_str);
	if ( xml_node_response_return == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No <return> element found:%s", error_str);
		return IAM_XML_ERROR;
	}
	if ( !response_status_xml(r->pool, xml_node_response_return, &error_str) ) {
		ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "User '%s' NOT authenticated", r->user);
		return IAM_ESB_ERROR;
	}
	*token           = extract_element_xml(r->pool, xml_soap_response, "//token",                &error_str);
	if ( token == NULL || error_str != NULL ) {
		return IAM_ESB_ERROR;
	}

	*token_type      = extract_element_xml(r->pool, xml_soap_response, "//tokenType",            &error_str);
	if ( token_type == NULL || error_str != NULL ) {
		return IAM_ESB_ERROR;
	}

	*expiration_time = extract_element_xml(r->pool, xml_soap_response, "//expirationTime",       &error_str);
	if ( expiration_time == NULL || error_str != NULL ) {
		return IAM_ESB_ERROR;
	}

	*create_time     = extract_element_xml(r->pool, xml_soap_response, "//createTime",           &error_str);
	if ( create_time == NULL || error_str != NULL ) {
		return IAM_ESB_ERROR;
	}

	*principal       = extract_element_xml(r->pool, xml_soap_response, "//principal",            &error_str);
	if ( principal == NULL || error_str != NULL ) {
		return IAM_ESB_ERROR;
	}

	return APR_SUCCESS;
}

/* http://wiki.openiam.com/display/IAMENGINEERING/SSO+-+Kerberos */
static apr_status_t api_cookie_data_from_principal(request_rec *r, const char *username, const char *uri,
	char **token_type, char **token, char **principal, char **user_id, char **expire)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	xmlNodePtr  xml_node_soap_command;
	xmlDocPtr   xml_soap_response;
	xmlNodePtr  xml_node_response_return;

	int         is_failed;
	const char *error_code;
	char       *error_str   = NULL;
	
	if ( uri == NULL ||
	     principal == NULL ) {
		return IAM_ERROR;
	}
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "get cookie data from URI and principal:%s, %s", uri, username);
	}
	xml_node_soap_command = create_api_command_xml(r->pool, "getCookieFromProxyURIAndPrincipal", "urn:idm.openiam.org/srvc/am/service", &error_str);
	if ( xml_node_soap_command == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "FEDERATE PROXY URI: create_api_command_xml error:%s", error_str);
		return IAM_XML_ERROR;
	}
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "principal", BAD_CAST username);
	xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "proxyURI",  BAD_CAST uri);
	xml_soap_response = parse_xml_content(r->pool, request_api_command_xml(r, xml_node_soap_command, dir_config->service_federation));
	if ( xml_soap_response == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "KERBEROS CONVERTING TO COOKIE: send_api_command returned NULL");
		return IAM_CURL_ERROR;
	}
	xml_node_response_return = find_node_xml(r->pool, xml_soap_response, "//return", &error_str);
	if ( xml_node_response_return == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No <return> element found. error:%s", error_str);
		return IAM_XML_ERROR;
	}
	is_failed = !response_status_xml(r->pool, xml_node_response_return, &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}
	if ( is_failed ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "get cookie data from principal:%s and uri:%s failed", username, uri);

		error_code = (const char*)xmlGetProp(xml_node_response_return, BAD_CAST "//errorCode");
		if ( error_code ) {
			log_federation_error_code(r, error_code);
		}
		return IAM_ESB_ERROR;
	}

	*token      = extract_element_xml(r->pool, xml_soap_response, "//token",          &error_str);
	*token_type = extract_element_xml(r->pool, xml_soap_response, "//tokenType",      &error_str);
	*expire     = extract_element_xml(r->pool, xml_soap_response, "//expirationTime", &error_str);
	*principal  = extract_element_xml(r->pool, xml_soap_response, "//principal",      &error_str);
	*user_id    = extract_element_xml(r->pool, xml_soap_response, "//userId",         &error_str);

	return (*token && *token_type && *expire && *principal && *user_id) ? APR_SUCCESS : IAM_ESB_ERROR;
}


/* http://wiki.openiam.com/display/IAMSUITEV3/Authentication+via+SOAP+API+-+login */
static apr_status_t api_login(request_rec *r, const char *username, const char *password,
	char **token_type, char **token, char **principal, char **user_id, char **expire)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	xmlNodePtr  xml_node_soap_command;
	xmlDocPtr   xml_soap_response;
	xmlNodePtr  xml_node_response_return;

	int         is_failed;
	char       *error_str   = NULL;

	if ( username == NULL || password == NULL ) {
		return IAM_ERROR;
	}
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "try to login using principal:%s", username);
	}

	xml_node_soap_command = create_api_command_xml(r->pool, "login", "http://service.auth.srvc.idm.openiam.org/", &error_str);
	if ( xml_node_soap_command == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "LOGIN: create_api_command_xml error:%s", error_str);
		return IAM_XML_ERROR;
	}
	xmlNodePtr requestNode = xmlNewChild(xml_node_soap_command, NULL, BAD_CAST "request", NULL);

	xmlNewChild(requestNode, NULL, BAD_CAST "principal", BAD_CAST username);
	xmlNewChild(requestNode, NULL, BAD_CAST "password",  BAD_CAST password);

	xml_soap_response = parse_xml_content(r->pool, request_api_command_xml(r, xml_node_soap_command, dir_config->service_auth));
	if ( xml_soap_response == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "LOGIN: send_api_command returned NULL");
		return IAM_CURL_ERROR;
	}
	xml_node_response_return = find_node_xml(r->pool, xml_soap_response, "//return", &error_str);
	if ( xml_node_response_return == NULL || error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "No <return> element found. error:%s", error_str);
		return IAM_XML_ERROR;
	}
	is_failed = !response_status_xml(r->pool, xml_node_response_return, &error_str);
	if ( error_str ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "%s", error_str);
	}
	if ( is_failed ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "login using principal:%s failed", username);
		return IAM_AUTH_ERROR;
	}

	*token      = extract_element_xml(r->pool, xml_soap_response, "//token",          &error_str);
	*token_type = extract_element_xml(r->pool, xml_soap_response, "//tokenType",      &error_str);
	*expire     = extract_element_xml(r->pool, xml_soap_response, "//expirationTime", &error_str);
	*principal  = extract_element_xml(r->pool, xml_soap_response, "//principal",      &error_str);
	*user_id    = extract_element_xml(r->pool, xml_soap_response, "//userId",         &error_str);

	return (*token && *token_type && *expire && *principal && *user_id) ? APR_SUCCESS : IAM_ESB_ERROR;
}


/* auth cookies */

static char* trim_quotes_from_cookie(char* cookie)
{
	apr_size_t l = strlen(cookie);
	char *result = cookie;
	if ( l > 2 ) {
		if ( cookie[0] == '\"' && cookie[l-1] == '\"' ) {
			cookie[l-1] = '\0';
			result = cookie + 1; // remove \" at the beginning
		}
	}
	return result;
}

static char* read_cookie(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	if ( dir_config->auth_cookie_regexp == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OPENIAM_CookieName not set");
		return NULL;
	}
	ap_regmatch_t regm[NUM_SUBS];
	const char *cookie_header = apr_table_get(r->headers_in, "Cookie");

	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "cookie header:%s cookie name:%s", cookie_header, dir_config->auth_cookie_name);
	}

	if ( cookie_header ) {
		if ( !ap_regexec(dir_config->auth_cookie_regexp, cookie_header, NUM_SUBS, regm, 0) ) {
			char *cookieval = NULL;
			/* Our regexp,
			 * ^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)
			 * only allows for $1 or $2 to be available. ($0 is always
			 * filled with the entire matched expression, not just
			 * the part in parentheses.) So just check for either one
			 * and assign to cookieval if present. */
			if ( regm[1].rm_so != -1 ) {
				cookieval = ap_pregsub(r->pool, "$1", cookie_header, NUM_SUBS, regm);
			}
			if ( regm[2].rm_so != -1 ) {
				cookieval = ap_pregsub(r->pool, "$2", cookie_header, NUM_SUBS, regm);
			}
			return trim_quotes_from_cookie(cookieval);
		} else {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "can't execute ap_regexec");
		}
	}
	return NULL;
}

static char* read_out_cookie(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	if ( dir_config->auth_cookie_regexp == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OPENIAM_CookieName not set");
		return NULL;
	}
	ap_regmatch_t regm[NUM_SUBS];
	const char *cookie_header = apr_table_get(r->headers_out, "Set-Cookie");

	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set cookie header:%s cookie name:%s", cookie_header, dir_config->auth_cookie_name);
	}

	if ( cookie_header ) {
		if ( !ap_regexec(dir_config->auth_cookie_regexp, cookie_header, NUM_SUBS, regm, 0) ) {
			char *cookieval = NULL;
			/* Our regexp,
			 * ^cookie_name=([^;]+)|;[ \t]+cookie_name=([^;]+)
			 * only allows for $1 or $2 to be available. ($0 is always
			 * filled with the entire matched expression, not just
			 * the part in parentheses.) So just check for either one
			 * and assign to cookieval if present. */
			if ( regm[1].rm_so != -1 ) {
				cookieval = ap_pregsub(r->pool, "$1", cookie_header, NUM_SUBS, regm);
			}
			if ( regm[2].rm_so != -1 ) {
				cookieval = ap_pregsub(r->pool, "$2", cookie_header, NUM_SUBS, regm);
			}
			return trim_quotes_from_cookie(cookieval);
		} else {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "can't execute ap_regexec. cookie_header=%s", cookie_header);
			}
		}
	}
	return NULL;
}


/* cookie look like: userId|principal|token|tokenType|[expiration_ms] */
static apr_status_t parse_cookie_3(apr_pool_t* p, char *cookie,
	char **user_id, char **principal,
	char **token, char **token_type, char **expiration_ms)
{
	char* delimeter = strchr(cookie, '|'); /* we can use strchr instead of mbschr becaouse cookie is in utf-8 ('|' < 0x80) */
	if ( delimeter == NULL ) {
		return OPENIAM_ERROR;
	}
	*delimeter = '\0';
	*user_id = cookie;

	cookie = delimeter + 1;
	delimeter = strchr(cookie, '|');
	if ( delimeter == NULL ) {
		return 1;
	}
	*delimeter = '\0';
	*principal = cookie;

	cookie = delimeter + 1;
	delimeter = strchr(cookie, '|');
	if ( delimeter == NULL ) {
		return 1;
	}
	*delimeter = '\0';
	*token = cookie;

	cookie = delimeter + 1;
	delimeter = strchr(cookie, '|');
	if ( delimeter == NULL ) {
		return 1;
	}
	*delimeter = '\0';
	*token_type = cookie;

	cookie = delimeter + 1;
	if ( expiration_ms != NULL ) {
		*expiration_ms = NULL;
		if ( cookie != NULL ) {
			delimeter = strchr(cookie, '|');
			*expiration_ms = cookie;
			if ( delimeter != NULL ) {
				*delimeter = '\0';
				cookie = delimeter + 1;
			} else {
				cookie = NULL;
			} 
		}
	}

	return APR_SUCCESS;
}

static const char* iam_cookie_domain(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config  = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	const char *domain = dir_config->auth_cookie_domain;
	const char *first_dot = NULL;
	if ( domain == NULL ) {
		first_dot = strchr(ap_get_server_name(r), '.');
		if ( first_dot ) {
			domain = first_dot;
		}
	}
	return domain;
}

static char* create_auth_cookie(request_rec *r, const char* cookie_data)
{
	iam_authn_dir_config_rec *dir_config  = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	const char *domain = iam_cookie_domain(r);

	if ( domain && dir_config->auth_cookie_name ) {
		if ( ap_http_scheme(r) && (strcasecmp(ap_http_scheme(r), "https") == 0) ) {
			return iam_pstrcat(r->pool, dir_config->auth_cookie_name, "=", cookie_data, "; Path=/; HttpOnly; Secure; Domain=", domain, NULL);
		} else {
			return iam_pstrcat(r->pool, dir_config->auth_cookie_name, "=", cookie_data, "; Path=/; HttpOnly; Domain=", domain, NULL);
		}
	}
	return NULL;
}

static const char* create_set_cookie(request_rec *r, const char* cookie_data)
{
	const char *domain = iam_cookie_domain(r);
	if ( domain ) {
		return iam_pstrcat(r->pool, cookie_data, "; HttpOnly; Domain=", domain, NULL);
	}
	return NULL;
}


/* encryption/decryption */

static apr_status_t init_crypto(request_rec *r)
{
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
	request_config->evp_ctx = apr_palloc(r->pool, sizeof(*request_config->evp_ctx));
	EVP_CIPHER_CTX_init(request_config->evp_ctx);
	apr_pool_cleanup_register(r->pool, request_config->evp_ctx, (void *)EVP_CIPHER_CTX_cleanup, apr_pool_cleanup_null);
	return APR_SUCCESS;
}

static char* iam_decrypt(request_rec* r, unsigned char* encoded, int len, int* result_len)
{
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	unsigned char* iv = encoded;

	if ( dir_config->evp_key_length == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "cant decrypt without key");
		return NULL;
	}
	if ( len < iv_size ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "encoded buff smaller than IV size");
		return NULL;
	}
	if ( request_config->evp_ctx == NULL ) {
		init_crypto(r);
	}
	memcpy(iv, encoded, iv_size);

	int ret;
	switch ( dir_config->evp_key_length ) {
		case 16: ret = EVP_DecryptInit_ex(request_config->evp_ctx, EVP_aes_128_cbc(), NULL, dir_config->evp_key, iv); break;
		case 24: ret = EVP_DecryptInit_ex(request_config->evp_ctx, EVP_aes_192_cbc(), NULL, dir_config->evp_key, iv); break;
		case 32: ret = EVP_DecryptInit_ex(request_config->evp_ctx, EVP_aes_256_cbc(), NULL, dir_config->evp_key, iv); break;
		default: return NULL;
	}
	if ( ret == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "EVP_DecryptInit_ex error=%s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	encoded = encoded + iv_size;
	int out_len = len - iv_size;
	unsigned char *plaintext = apr_pcalloc(r->pool, out_len + 1);
	if ( EVP_DecryptUpdate(request_config->evp_ctx, plaintext, &out_len, encoded, out_len) == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Decryption error. Possible key in ESB differ with key in proxy cache. Restarting apache can solve problem. EVP_DecryptUpdate return error=%s buff=%s", ERR_error_string(ERR_get_error(), NULL), plaintext);
		return NULL;
	}
	unsigned char* last_buf = encoded + out_len;
	if ( EVP_DecryptFinal(request_config->evp_ctx, last_buf, &len) == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Decryption error. Possible key in ESB differ with key in proxy cache. Restarting apache can solve problem. EVP_DecryptFinal return error=%s buff=%s", ERR_error_string(ERR_get_error(), NULL), plaintext);
		return NULL;
	}
	len = len + out_len;
	if ( result_len ) {
		*result_len = len;
	}
	plaintext[len] = '\0';
	return (char*)plaintext;
}

static unsigned char* iam_encrypt(request_rec* r, unsigned char* buffer, int len, int* result_len)
{
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config,  &iam_authn_module);
	if ( request_config->evp_ctx == NULL ) {
		init_crypto(r);
	}
	if ( dir_config->evp_key_length == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "cant decrypt without key");
		return NULL;
	}
	unsigned char iv[iv_size];
	if ( !RAND_bytes(iv, iv_size) ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "PRNG is not seeded");
	}
	int ret;
	switch ( dir_config->evp_key_length ) {
		case 16: ret = EVP_EncryptInit_ex(request_config->evp_ctx, EVP_aes_128_cbc(), NULL, dir_config->evp_key, iv); break;
		case 24: ret = EVP_EncryptInit_ex(request_config->evp_ctx, EVP_aes_192_cbc(), NULL, dir_config->evp_key, iv); break;
		case 32: ret = EVP_EncryptInit_ex(request_config->evp_ctx, EVP_aes_256_cbc(), NULL, dir_config->evp_key, iv); break;
		default: return NULL;
	}
	if ( ret == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "EVP_EncryptInit_ex error=%s", ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}
	int out_len = len + AES_BLOCK_SIZE;
	unsigned char *encoded = apr_pcalloc(r->pool, out_len + iv_size);
	memcpy(encoded, iv, iv_size);
	if ( EVP_EncryptUpdate(request_config->evp_ctx, encoded + iv_size, &out_len, buffer, len) == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "EVP_EncryptUpdate return error=%s enc=%s", ERR_error_string(ERR_get_error(), NULL), encoded);
		return NULL;
	}
	unsigned char* last_buf = encoded + iv_size + out_len;
	if ( EVP_EncryptFinal(request_config->evp_ctx, last_buf, &len) == 0 ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "EVP_EncryptFinal return error=%s enc=%s", ERR_error_string(ERR_get_error(), NULL), encoded);
		return NULL;
	}
	len = len + out_len + iv_size;
	if ( result_len ) {
		*result_len = len;
	}
	return encoded;
}

static char* iam_decrypt_cookie(request_rec *r, const char *cookie)
{
	int res_len = 0;
	char *result = NULL;
	int l = apr_base64_decode_len(cookie);
	if ( l > 1 ) {
		unsigned char* decoded_cookie = apr_pcalloc(r->pool, l);
		l = apr_base64_decode((char*)decoded_cookie, cookie);
		if ( l > 0 ) {
			result = iam_decrypt(r, decoded_cookie, l, &res_len);
			if ( res_len > 0 ) {
				return result;
			}
		}
	}
	return NULL;
}

static char* iam_encrypt_cookie(request_rec *r, const char *cookie)
{
	int l = 0;
	int base64_len;
	char* encoded_cookie;
	const unsigned char *encrypted = iam_encrypt(r, (unsigned char*)cookie, strlen(cookie)+1, &l);
	if ( encrypted && (l > 0) ) {
		base64_len = apr_base64_encode_len(l);
		if ( base64_len > 0 ) {
			encoded_cookie = apr_palloc(r->pool, base64_len);
			l = apr_base64_encode(encoded_cookie, (const char*)encrypted, l);
			if ( l > 0 ) {
				return encoded_cookie;
			}
		}
	}
	return NULL;
}

/* copied from mod_proxy.c */

static int reverse_proxy_to(request_rec *r, char* url)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
	const char* host   = apr_table_get(r->headers_in, "Host");
	const char* scheme = ap_http_scheme(r);

	iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);
	if ( server_config->proxypass_reverse ) {
		request_config->ralias_fake = apr_pstrcat(r->pool, server_config->proxypass_reverse, "/", NULL);
	} else {
		request_config->ralias_fake = ap_construct_url(r->pool, "/", r);
	}
	request_config->cookie_fake = apr_pstrcat(r->pool, s_domain, iam_cookie_domain(r), NULL);

	if ( is_unset_allcookies(r) ) {
		const char *cookie_before = apr_table_get(r->headers_in, "Cookie");
		apr_table_set(r->headers_in, "Cookie", "");
		const char *cookie_after = apr_table_get(r->headers_in, "Cookie");
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "remove cookies for %s. was %s now %s", r->uri, cookie_before, cookie_after);
		}
	}

	r->proxyreq = PROXYREQ_REVERSE;
	r->handler  = "proxy-server";
	if ( strncasecmp(url, "proxy:", 6) == 0 ) { /* strlen("proxy:") = 6 */
		r->filename = url;
		r->uri = apr_pstrdup(r->pool, url + 6);
	} else {
		r->filename = apr_pstrcat(r->pool, "proxy:", url, NULL);
		r->uri = url; 
	}
	r->hostname = extract_server_from_url(r->pool, url, 0, NULL);

	request_config->ralias_real = extract_server_from_url(r->pool, r->filename + 6, 1, NULL);

	apr_table_setn(r->headers_in, s_proxy_host_header, host ? host : r->hostname);
	if ( scheme && dir_config->is_send_scheme ) {
		apr_table_setn(r->headers_in, s_proxy_scheme_header, scheme); 
	}
	if ( r->hostname ) {
		apr_table_setn(r->headers_in, "Host", r->hostname); 
	}
	/*
	if ( r->main ) {
		r->main = NULL;
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "R-PROXY: r->main for (%s)was not NULL", url);
	}
	*/
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "R-PROXY: looking for worker for (%s)", request_config->ralias_real);
	}
	proxy_server_conf *proxy_conf = (proxy_server_conf*) ap_get_module_config(r->server->module_config, &proxy_module);
#ifdef APACHE_24
	proxy_worker *worker = ap_proxy_get_worker(r->pool, NULL, proxy_conf, request_config->ralias_real);
#else
	proxy_worker *worker = ap_proxy_get_worker(r->pool, proxy_conf, request_config->ralias_real);
#endif
	if ( worker ) {
		char *worker_name
#ifdef APACHE_24
			= ap_proxy_worker_name(r->pool, worker);
#else
			= (char*)worker->name;
#endif
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "R-PROXY: found worker (%s)", worker_name);
		}
	} else {
		const char *err 
#ifdef APACHE_24
			= ap_proxy_define_worker(r->server->process->pool, &worker, NULL, proxy_conf, request_config->ralias_real, 1);
#else
			= ap_proxy_add_worker(&worker, r->server->process->pool, proxy_conf, request_config->ralias_real);
#endif
		if ( err ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "R-PROXY: error adding worker %s", err);
			return OPENIAM_RPROXY_ERROR;
		}

#ifdef APACHE_24
		ap_proxy_initialize_worker(worker, r->server, r->server->process->pool);
#else
		ap_proxy_initialize_worker_share(proxy_conf, worker, r->server);
		ap_proxy_initialize_worker(worker, r->server);
#endif

		worker->s->status |= PROXY_WORKER_IGNORE_ERRORS;

#ifdef APACHE_24
		worker->s->recv_buffer_size = 0;
		worker->s->recv_buffer_size_set = 1;

		worker->s->io_buffer_size   = AP_IOBUFSIZE; 
		worker->s->io_buffer_size_set = 1;

		worker->s->retry            = 0;
		worker->s->retry_set        = 1;

		if ( dir_config->rproxy_ttl > 0 ) {
			worker->s->ttl              = apr_time_from_sec(dir_config->rproxy_ttl);
		} else {
			worker->s->ttl              = apr_time_from_sec(1200);
		}

		if ( dir_config->rproxy_timeout > 0 ) {
			worker->s->timeout          = apr_time_from_sec(dir_config->rproxy_timeout);
			worker->s->timeout_set      = 1;
		} else {
			worker->s->timeout          = apr_time_from_sec(1200);
			worker->s->timeout_set      = 1;
		}

		//worker->s->acquire          = 1000;
		worker->s->acquire_set      = 0;

		worker->s->keepalive        = 1;
		worker->s->keepalive_set    = 1;

		worker->s->disablereuse     = 0;
		worker->s->disablereuse_set = 1;

#else
		worker->recv_buffer_size = 0;
		worker->recv_buffer_size_set = 1;

		worker->io_buffer_size   = AP_IOBUFSIZE; 
		worker->io_buffer_size_set = 1;

		worker->retry            = 0;
		worker->retry_set        = 1;


		if ( dir_config->rproxy_ttl > 0 ) {
			worker->ttl              = apr_time_from_sec(dir_config->rproxy_ttl);
		} else {
			worker->ttl              = apr_time_from_sec(1200);
		}

		if ( dir_config->rproxy_timeout > 0 ) {
			worker->timeout          = apr_time_from_sec(dir_config->rproxy_timeout);
			worker->timeout_set      = 1;
		} else {
			worker->timeout          = apr_time_from_sec(1200);
			worker->timeout_set      = 1;
		}

		//worker->acquire          = 1000;
		worker->acquire_set      = 0;

		worker->keepalive        = 1;
		worker->keepalive_set    = 1;

		worker->disablereuse     = 0;
		worker->disablereuse_set = 1;
#endif
		char *worker_name
#ifdef APACHE_24
			= ap_proxy_worker_name(r->pool, worker);
#else
			= (char*)worker->name;
#endif
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "R-PROXY: added worker (%s)", worker_name);
		}
	}

	return OK;
}

static char* create_cookie_from_id_and_token_3(
		apr_pool_t* pool,
		const char *user_id,
		const char *principal,
		const char *token,
		const char *token_type,
		const char *expiration_time_in_ms)
{
	return iam_pstrcat(pool, user_id, "|", principal, "|", token, "|", token_type, "|", expiration_time_in_ms, NULL);
}


/* KERBEROS ATHENTICATION ******************************************************************************************************************/


/* ported from mod_auth_kerb. Only Kerberos v5 supported for now */

#if !defined(HEIMDAL)
/* Needed to work around problems with replay caches */

/* This is our replacement krb5_rc_store function */
static krb5_error_code KRB5_LIB_FUNCTION mod_auth_kerb_rc_store(krb5_context context, krb5_rcache rcache,
                       krb5_donot_replay_internal *donot_replay)
{
	return 0;
}

/* And this is the operations vector for our replay cache */
const krb5_rc_ops_internal mod_auth_kerb_rc_ops = {
	0,
	"dfl",
	krb5_rc_dfl_init,
	krb5_rc_dfl_recover,
	krb5_rc_dfl_destroy,
	krb5_rc_dfl_close,
	mod_auth_kerb_rc_store,
	krb5_rc_dfl_expunge,
	krb5_rc_dfl_get_span,
	krb5_rc_dfl_get_name,
	krb5_rc_dfl_resolve
};
#endif


static void set_kerb_auth_headers(request_rec *r, iam_authn_dir_config_rec *dir_config, int use_krb5pwd, char *negotiate_ret_value)
{
	char *negoauth_param;
	const char *header_name = (r->proxyreq == PROXYREQ_PROXY) ? "Proxy-Authenticate" : "WWW-Authenticate";

	if ( negotiate_ret_value != NULL ) {
		negoauth_param = (*negotiate_ret_value == '\0')
			? MECH_NEGOTIATE
			: apr_pstrcat(r->pool, MECH_NEGOTIATE " ", negotiate_ret_value, NULL);
		apr_table_add(r->err_headers_out, header_name, negoauth_param);
		if ( dir_config->is_debug_kerb ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set error headers to %s %s", header_name, negoauth_param);
		}
	}
}

#ifdef _WIN32
int mkstemp(char *template)
{
	int start, i;
	pid_t val;
	val = getpid();
	start = strlen(template) - 1;
	while ( template[start] == 'X' ) {
		template[start] = '0' + val % 10;
		val /= 10;
		start--;
	}

	while ( 1 ) {
		int fd;
		fd = open(template, O_RDWR | O_CREAT | O_EXCL, 0600);
		if( fd >= 0 || errno != EEXIST ) {
			return fd;
		}
		i = start + 1;
		while ( 1 ) {
			if ( template[i] == 0 ) {
				return -1;
			}
			template[i]++;
			if ( template[i] == '9' + 1 ) {
				template[i] = 'a';
			}
			if ( template[i] <= 'z' ) {
				break;
			}
			template[i] = 'a';
			i++;
		}
	} 
}
#endif

static int krb5_cache_cleanup(void *data)
{
	krb5_context context;
	krb5_ccache  cache;
	krb5_error_code problem;
	char *cache_name = (char *) data;

	problem = krb5_init_context(&context);
	if ( problem ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "krb5_init_context() failed in krb5_cache_cleanup()");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	problem = krb5_cc_resolve(context, cache_name, &cache);
	if ( problem ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "krb5_cc_resolve() failed (%s: %s) in krb5_cache_cleanup()", cache_name, krb5_get_err_text(context, problem));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	krb5_cc_destroy(context, cache);
	krb5_free_context(context);
	return OK;
}

static int create_krb5_ccache(krb5_context kcontext,
				request_rec *r,
				krb5_principal princ,
				krb5_ccache *ccache)
{
	char *ccname;
	int fd;
	krb5_error_code problem;
	int ret;
	krb5_ccache tmp_ccache = NULL;
	OM_uint32 minor_status;

	ccname = apr_psprintf(r->pool, "FILE:%s/krb5cc_apache_XXXXXX", P_tmpdir);
	fd = mkstemp(ccname + strlen("FILE:"));
	if ( fd < 0 ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mkstemp() failed: %s", strerror(errno));
		ret = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}
	close(fd);

	problem = krb5_cc_resolve(kcontext, ccname, &tmp_ccache);
	if ( problem ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "krb5_cc_resolve() failed: %s", krb5_get_err_text(kcontext, problem));
		ret = HTTP_INTERNAL_SERVER_ERROR;
		unlink(ccname);
		goto end;
	}

	problem = krb5_cc_initialize(kcontext, tmp_ccache, princ);
	if ( problem ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"Cannot initialize krb5 ccache %s: krb5_cc_initialize() failed: %s",
			ccname, krb5_get_err_text(kcontext, problem));
		ret = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}

	apr_table_setn(r->subprocess_env, "KRB5CCNAME", ccname);
	apr_pool_cleanup_register(r->pool, ccname, krb5_cache_cleanup, apr_pool_cleanup_null);

	problem = gss_krb5_ccache_name( &minor_status, ccname, NULL); 
	if ( problem != GSS_S_COMPLETE ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Error calling gss_krb5_ccache_name to set ccache to %s, error: %s minor_status: %d",
			ccname, krb5_get_err_text(kcontext, problem), minor_status); 
	}

	*ccache = tmp_ccache;
	tmp_ccache = NULL;

	ret = OK;

end:
	if ( tmp_ccache ) {
		krb5_cc_destroy(kcontext, tmp_ccache);
	}
	return ret;
}

/*********************************************************************
 * GSSAPI Authentication
 ********************************************************************/

static const char * get_gss_error(request_rec *r, OM_uint32 err_maj, OM_uint32 err_min, char *prefix)
{
	OM_uint32 maj_stat, min_stat;
	OM_uint32 msg_ctx = 0;
	gss_buffer_desc status_string;
	char *err_msg;
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_debug_kerb ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"GSS-API major_status:%8.8x, minor_status:%8.8x", err_maj, err_min);
	}
	err_msg = apr_pstrdup(r->pool, prefix);
	do {
		maj_stat = gss_display_status (&min_stat,
						err_maj,
						GSS_C_GSS_CODE,
						GSS_C_NO_OID,
						&msg_ctx,
						&status_string);
		if ( !GSS_ERROR(maj_stat) ) {
			err_msg = apr_pstrcat(r->pool, err_msg, ": ", (char*)status_string.value, NULL);
			gss_release_buffer(&min_stat, &status_string);
		}
	} while (!GSS_ERROR(maj_stat) && msg_ctx != 0);

	msg_ctx = 0;
	err_msg = apr_pstrcat(r->pool, err_msg, " (", NULL);
	do {
		maj_stat = gss_display_status (&min_stat,
						err_min,
						GSS_C_MECH_CODE,
						GSS_C_NULL_OID,
						&msg_ctx,
						&status_string);
		if ( !GSS_ERROR(maj_stat) ) {
			err_msg = apr_pstrcat(r->pool, err_msg, ", ", (char *) status_string.value, NULL);
			gss_release_buffer(&min_stat, &status_string);
		}
	} while (!GSS_ERROR(maj_stat) && msg_ctx != 0);
	err_msg = apr_pstrcat(r->pool, err_msg, ")", NULL);
    
	return err_msg;
}

static int store_gss_creds(request_rec *r, char *princ_name, gss_cred_id_t delegated_cred)
{
	OM_uint32 maj_stat, min_stat;
	krb5_principal princ = NULL;
	krb5_ccache ccache = NULL;
	krb5_error_code problem;
	krb5_context context;
	int ret = HTTP_INTERNAL_SERVER_ERROR;
    
	problem = krb5_init_context(&context);
	if ( problem ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Cannot initialize krb5 context");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	problem = krb5_parse_name(context, princ_name, &princ);
	if ( problem ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"Cannot parse delegated username (%s)", krb5_get_err_text(context, problem));
		goto end;
	}

	problem = create_krb5_ccache(context, r, princ, &ccache);
	if ( problem ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"Cannot create krb5 ccache (%s)", krb5_get_err_text(context, problem));
		goto end;
	}

	maj_stat = gss_krb5_copy_ccache(&min_stat, delegated_cred, ccache);
	if ( GSS_ERROR(maj_stat) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"Cannot store delegated credential (%s)",
			get_gss_error(r, maj_stat, min_stat, "gss_krb5_copy_ccache"));
		goto end;
	}

	krb5_cc_close(context, ccache);
	ccache = NULL;
	ret = 0;
    
end:
	if ( princ ) {
		krb5_free_principal(context, princ);
	}
	if ( ccache ) {
		krb5_cc_destroy(context, ccache);
	}
	krb5_free_context(context);
	return ret;
}

static int get_gss_creds(request_rec *r, iam_authn_dir_config_rec *dir_config, gss_cred_id_t *server_creds)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major_status, minor_status, minor_status2;
	gss_name_t server_name = GSS_C_NO_NAME;
	char buf[1024];
	int have_server_princ;
    
	have_server_princ = dir_config->krb_service_name && strchr(dir_config->krb_service_name, '/') != NULL;
	if ( have_server_princ ) {
		strncpy(buf, dir_config->krb_service_name, sizeof(buf));
	} else if ( dir_config->krb_service_name && strcmp(dir_config->krb_service_name, "Any") == 0 ) {
		*server_creds = GSS_C_NO_CREDENTIAL;
		return 0;
	} else {
		snprintf(buf, sizeof(buf), "%s@%s", 
			(dir_config->krb_service_name) ? dir_config->krb_service_name : SERVICE_NAME,
			ap_get_server_name(r));
	}

	if ( dir_config->is_debug_kerb ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "kerberos: service name: %s", buf);
	}

	token.value  = buf;
	token.length = strlen(buf) + 1;
    
	major_status = gss_import_name(&minor_status, &token,
					(have_server_princ) ? (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME : (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
					&server_name);
	memset(&token, 0, sizeof(token));
	if ( GSS_ERROR(major_status) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", get_gss_error(r, major_status, minor_status, "gss_import_name() failed"));
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	major_status = gss_display_name(&minor_status, server_name, &token, NULL);
	if ( GSS_ERROR(major_status) ) {
		/* Perhaps we could just ignore this error but it's safer to give up now,
		I think */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"%s", get_gss_error(r, major_status, minor_status,
			"gss_display_name() failed"));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
    
	if ( dir_config->is_debug_kerb ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Acquiring creds for %s", (char*)token.value);
	}
	gss_release_buffer(&minor_status, &token);
    
	major_status = gss_acquire_cred(&minor_status, server_name, GSS_C_INDEFINITE,
					    GSS_C_NO_OID_SET, GSS_C_ACCEPT,
					    server_creds, NULL, NULL);
	gss_release_name(&minor_status2, &server_name);
	if ( GSS_ERROR(major_status) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"%s", get_gss_error(r, major_status, minor_status,
			"gss_acquire_cred() failed"));
		return HTTP_INTERNAL_SERVER_ERROR;
	}
    
	return 0;
}

static int cmp_gss_type(gss_buffer_t token, gss_OID oid)
{
	unsigned char *p;
	size_t len;
    
	if ( token->length == 0 ) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
    
	p = token->value;
	if ( *p++ != 0x60 ) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
	len = *p++;
	if ( len & 0x80 ) {
		if ( (len & 0x7f) > 4 ) {
			return GSS_S_DEFECTIVE_TOKEN;
		}
		p += len & 0x7f;
	}
	if ( *p++ != 0x06 ) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
    
	if ( ((OM_uint32) *p++) != oid->length ) {
		return GSS_S_DEFECTIVE_TOKEN;
	}
    
	return memcmp(p, oid->elements, oid->length);
}

static int authenticate_user_gss(request_rec *r, iam_authn_dir_config_rec *dir_config, const char *auth_line, char **negotiate_ret_value)
{
	OM_uint32 major_status, minor_status, minor_status2;
	gss_buffer_desc input_token  = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
	const char *auth_param = NULL;
	int ret;
	gss_name_t client_name = GSS_C_NO_NAME;
	gss_cred_id_t delegated_cred = GSS_C_NO_CREDENTIAL;
	OM_uint32 (KRB5_LIB_FUNCTION *accept_sec_token)(OM_uint32 *, gss_ctx_id_t *, const gss_cred_id_t,
							const gss_buffer_t, const gss_channel_bindings_t,
							gss_name_t *, gss_OID *, gss_buffer_t, OM_uint32 *,
							OM_uint32 *, gss_cred_id_t *);
	gss_OID_desc spnego_oid;
	gss_ctx_id_t  context      = GSS_C_NO_CONTEXT;
	gss_cred_id_t server_creds = GSS_C_NO_CREDENTIAL;
	OM_uint32 ret_flags = 0;

	*negotiate_ret_value = "\0";

	spnego_oid.length = 6;
	spnego_oid.elements = (void *)"\x2b\x06\x01\x05\x05\x02";

	if ( dir_config->krb_keytab ) {
		char *ktname;
		/* we don't use the ap_* calls here, since the string passed to putenv()
		 * will become part of the enviroment and shouldn't be free()ed by apache
		 */
		ktname = malloc(strlen("KRB5_KTNAME=") + strlen(dir_config->krb_keytab) + 1);
		if ( ktname == NULL ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "malloc() failed: not enough memory");
			ret = HTTP_INTERNAL_SERVER_ERROR;
			goto end;
		}
		sprintf(ktname, "KRB5_KTNAME=%s", dir_config->krb_keytab);
		putenv(ktname);
		if ( dir_config->is_debug_kerb ) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "KRB5_KTNAME=%s", dir_config->krb_keytab);
		}

#ifdef HEIMDAL
		/* Seems to be also supported by latest MIT */
		gsskrb5_register_acceptor_identity(dir_config->krb_keytab);
#endif
	}

	ret = get_gss_creds(r, dir_config, &server_creds);
	if ( ret ) {
		goto end;
	}

	/* ap_getword() shifts parameter */
	auth_param = ap_getword_white(r->pool, &auth_line);
	if ( auth_param == NULL ) {
		if ( dir_config->is_debug_kerb ) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "No Authorization parameter in request from client");
		}
		ret = DECLINED; // UNAUTHORIZED, but just skip kerberos
		goto end;
	}
    
	input_token.length = apr_base64_decode_len(auth_param) + 1;
	input_token.value = apr_pcalloc(r->connection->pool, input_token.length);
	if ( input_token.value == NULL ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc() failed (not enough memory)");
		ret = HTTP_INTERNAL_SERVER_ERROR;
		goto end;
	}
	input_token.length = apr_base64_decode(input_token.value, auth_param);
    
#ifdef GSSAPI_SUPPORTS_SPNEGO
	accept_sec_token = gss_accept_sec_context;
#else
	accept_sec_token = (cmp_gss_type(&input_token, &spnego_oid) == 0) ? gss_accept_sec_context_spnego : gss_accept_sec_context;
#endif
	if ( dir_config->is_debug_kerb ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Verifying client data using KRB5 GSS-API %s",
				(accept_sec_token == gss_accept_sec_context) ? "" : "with our SPNEGO lib");
	}
	major_status = accept_sec_token(&minor_status,
					&context,
					server_creds,
					&input_token,
					GSS_C_NO_CHANNEL_BINDINGS,
					&client_name,
					NULL,
					&output_token,
					&ret_flags,
					NULL,
					&delegated_cred);
	if ( dir_config->is_debug_kerb ) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Client %s us their credential", (ret_flags & GSS_C_DELEG_FLAG) ? "delegated" : "didn't delegate");
	}
	if ( output_token.length ) {
		char *token = NULL;
		size_t len;

		len = apr_base64_encode_len(output_token.length) + 1;
		token = apr_pcalloc(r->connection->pool, len + 1);
		if ( token == NULL ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "ap_pcalloc() failed (not enough memory)");
			ret = HTTP_INTERNAL_SERVER_ERROR;
			gss_release_buffer(&minor_status2, &output_token);
			goto end;
		}
		apr_base64_encode(token, output_token.value, output_token.length);
		token[len] = '\0';
		*negotiate_ret_value = token;
		if ( dir_config->is_debug_kerb ) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "GSS-API token of length %ld bytes will be sent back", output_token.length);
		}
		gss_release_buffer(&minor_status2, &output_token);
		set_kerb_auth_headers(r, dir_config, 0, *negotiate_ret_value);
	}
    
	if ( GSS_ERROR(major_status) ) {
		if ( input_token.length > 7 && memcmp(input_token.value, "NTLMSSP", 7) == 0 ) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Warning: received token seems to be NTLM, which isn't supported by the Kerberos module. Check your IE configuration.");
		}
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", get_gss_error(r, major_status, minor_status, "gss_accept_sec_context() failed"));
		/* Don't offer the Negotiate method again if call to GSS layer failed */
		*negotiate_ret_value = NULL;
		ret = DECLINED; // UNAUTHORIZED, but just skip kerberos
		goto end;
	}
    
#if 0
	/* This is a _Kerberos_ module so multiple authentication rounds aren't
	 * supported. If we wanted a generic GSS authentication we would have to do
	 * some magic with exporting context etc. */
	if ( major_status & GSS_S_CONTINUE_NEEDED ) {
		ret = HTTP_UNAUTHORIZED;
		goto end;
	}
#endif

	major_status = gss_display_name(&minor_status, client_name, &output_token, NULL);
	gss_release_name(&minor_status, &client_name);
	if ( GSS_ERROR(major_status) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s", get_gss_error(r, major_status, minor_status, "gss_display_name() failed"));
		ret = DECLINED; // UNAUTHORIZED, but just skip kerberos
		goto end;
	}

	r->ap_auth_type = AUTH_TYPE_OPENIAM;
	char *user_name = apr_pstrdup(r->pool, output_token.value);
	if ( dir_config->krb_principal_only ) {
		char *a = strchr(user_name, '@');
		if ( a ) {
			*a = '\0';
		}
	}
	if ( dir_config->krb_principal_prefix ) {
		r->user = apr_pstrcat(r->pool, dir_config->krb_principal_prefix, user_name, dir_config->krb_principal_suffix, NULL);
	} else if ( dir_config->krb_principal_suffix ) {
		r->user = apr_pstrcat(r->pool, user_name, dir_config->krb_principal_suffix, NULL);
	} else {
		r->user = user_name;
	}

	if ( dir_config->krb_save_credentials && delegated_cred != GSS_C_NO_CREDENTIAL ) {
		store_gss_creds(r, (char *)output_token.value, delegated_cred);
	}

	gss_release_buffer(&minor_status, &output_token);
    
	ret = OK;

end:
	if ( delegated_cred ) {
		gss_release_cred(&minor_status, &delegated_cred);
	}

	if ( output_token.length ) {
		gss_release_buffer(&minor_status, &output_token);
	}

	if ( client_name != GSS_C_NO_NAME ) {
		gss_release_name(&minor_status, &client_name);
	}

	if ( server_creds != GSS_C_NO_CREDENTIAL ) {
		gss_release_cred(&minor_status, &server_creds);
	}

	if ( context != GSS_C_NO_CONTEXT ) {
		gss_delete_sec_context(&minor_status, &context, GSS_C_NO_BUFFER);
	}

	return ret;
}

static krb5_conn_data* already_succeeded(request_rec *r, iam_authn_dir_config_rec *dir_config, char *auth_line)
{
	krb5_conn_data *conn_data;
	char keyname[1024];

	snprintf(keyname, sizeof(keyname) - 1,
		"mod_iam_authn::connection::%s::%ld",
#ifdef APACHE_24
		r->connection->client_ip,
#else
		r->connection->remote_ip,
#endif
		r->connection->id);

	if ( apr_pool_userdata_get((void**)&conn_data, keyname, r->connection->pool) != 0 ) {
		return NULL;
	}

	if( conn_data ) {
		if( strcmp(conn_data->authline, auth_line) == 0 ) {
			if ( dir_config->is_debug_kerb ) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "matched previous auth request");
			}
			return conn_data;
		}
	}
	return NULL;
}

static int kerb_authenticate_user(request_rec *r)
{
	krb5_conn_data *prevauth = NULL;
	const char *auth_type = NULL;
	char *auth_line = NULL;
	char *negotiate_ret_value = NULL;
	char keyname[1024];
	apr_status_t ret;
	iam_authn_dir_config_rec     *dir_config     = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	if ( dir_config->is_debug_kerb ) { 
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "kerb_authenticate_user entered with user %s ", r->user);
	}
	/* get what the user sent us in the HTTP header */
	auth_line = (char *)apr_table_get(r->headers_in, (r->proxyreq == PROXYREQ_PROXY) ? "Proxy-Authorization" : "Authorization");
	if ( !auth_line ) {
		set_kerb_auth_headers(r, dir_config, 0, "\0");
		if ( dir_config->is_debug_kerb ) { 
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "auth line is empty. returns negotiate");
		}
		iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
		if ( request_config->password_auth  ) { /* do refresh to login form only if password auth enabled */
			const char *request_url = dir_config->on_auth_redirect ? dir_config->on_auth_redirect : r->unparsed_uri;
			if ( request_url ) {
				request_url = iam_escape_uri(r->pool, request_url);
			}
			apr_table_set(r->err_headers_out, "Refresh", apr_pstrcat(r->pool, "0;url=", ap_construct_url(r->pool, dir_config->login_url, r), dir_config->postback_param, request_url, NULL));
			if ( dir_config->is_debug_kerb ) { 
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "include refresh login url in negotiate response");
			}
		}
		return HTTP_UNAUTHORIZED;
	}
	auth_type = ap_getword_white(r->pool, (const char **)&auth_line);
	if ( dir_config->is_debug_kerb ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
			"kerb_authenticate_user %s is %s AuthType=%s",
			(r->proxyreq == PROXYREQ_PROXY) ? "Proxy-Authorization" : "Authorization",
    			auth_line, auth_type);
	}

	if ( (prevauth = already_succeeded(r, dir_config, auth_line)) == NULL) {
		ret = HTTP_UNAUTHORIZED;
		if ( strcasecmp(auth_type, MECH_NEGOTIATE) == 0) {
			ret = authenticate_user_gss(r, dir_config, auth_line, &negotiate_ret_value);
		}

		if ( ret == HTTP_UNAUTHORIZED ) {
			set_kerb_auth_headers(r, dir_config, 0, negotiate_ret_value);
		}
	} else {
		ret = prevauth->last_return;
		r->user = prevauth->user;
		r->ap_auth_type = prevauth->mech;
	}

	/*
	* save who was auth'd, if it's not already stashed.
	*/
	if( !prevauth ) {
		prevauth = (krb5_conn_data *) apr_pcalloc(r->connection->pool, sizeof(krb5_conn_data));
		prevauth->user = apr_pstrdup(r->connection->pool, r->user);
		prevauth->authline = apr_pstrdup(r->connection->pool, auth_line);
		prevauth->mech = apr_pstrdup(r->connection->pool, auth_type);
		prevauth->last_return = ret;
		snprintf(keyname, sizeof(keyname) - 1,
			"mod_iam_authn::connection::%s::%ld",
#ifdef APACHE_24
			r->connection->client_ip, 
#else
			r->connection->remote_ip, 
#endif
			r->connection->id);
		apr_pool_userdata_set(prevauth, keyname, NULL, r->connection->pool);
	}

	if ( ret == OK ) {
		if ( dir_config->is_debug_kerb ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "kerberos: user %s authenticated", r->user);
		}
	}

	return ret;
}

static apr_table_t* iam_request_arguments(request_rec *r)
{
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);
	if ( request_config->arguments ) {
		return request_config->arguments;
	}
	request_config->arguments = apr_table_make(r->pool, 10);

	/* parse arguments */
	char *start = r->args;
	while ( start && *start ) {
		char *param_value = NULL;
		char *end = strchr(start, '&');
		if ( end ) {
			apr_size_t len = end - start;
			param_value = apr_palloc(r->pool, len + 1);
			memcpy(param_value, start, len);
			param_value[len] = '\0';
			start = end + 1;
		} else {
			param_value = apr_pstrdup(r->pool, start);
			start = NULL;
		}
		if ( param_value ) {
			char* key  = param_value;
			char* value = NULL;
			char* equal = strchr(key, '=');
			if ( equal ) {
				*equal = '\0';
				value = equal + 1;
			}
			if ( value ) {
				apr_table_setn(request_config->arguments, key, value);
			} else {
				apr_table_setn(request_config->arguments, key, "");
			}
		}
	}

	return request_config->arguments;
}

/* AUTHENTICATION ***************************************************************************************************************************/

apr_status_t openiam_set_request_noauth(request_rec *r)
{
	r->ap_auth_type = AUTH_TYPE_OPENIAM_NOAUTH;
	if ( r->user == NULL ) {
		r->user = OPENIAM_AUTH_ANONYMOUS_NAME;
	}
	return APR_SUCCESS;
}

static void set_and_comp_redirect_regexp(iam_authn_dir_config_rec* dir_config, apr_pool_t *p, const char *cookie_name)
{
	if ( dir_config->on_logout_redirect_cookie_regexp ) {
		return; // it is already set.
	}
	int danger_chars = 0;
	const char *sp = cookie_name;
	const char* regexp_string;
	/* The goal is to end up with this regexp,
	 * ^cookie_name=([^;,]+)|[;,][ \t]+cookie_name=([^;,]+)
	 * with cookie_name obviously substituted either
	 * with the real cookie name set by the user in httpd.conf, or with the
	 * default COOKIE_NAME. */
	/* Anyway, we need to escape the cookie_name before pasting it
	 * into the regex
	 */
	while ( *sp ) {
		if ( !apr_isalnum(*sp) ) {
			++danger_chars;
		}
        ++sp;
	}
	if ( danger_chars ) {
		char *cp = apr_palloc(p, sp - cookie_name + danger_chars + 1); /* 1 == \0 */
		sp = cookie_name;
		cookie_name = cp;
		while ( *sp ) {
			if ( !apr_isalnum(*sp) ) {
				*cp++ = '\\';
			}
			*cp++ = *sp++;
		}
		*cp = '\0';
	}
	regexp_string = apr_pstrcat(p, "^", cookie_name, "=([^;,]+)|[;,][ \t]*", cookie_name, "=([^;,]+)", NULL);
	if ( regexp_string ) {
		dir_config->on_logout_redirect_cookie_regexp = ap_pregcomp(p, regexp_string, AP_REG_EXTENDED);
	}
	if ( dir_config->on_logout_redirect_cookie_regexp && (dir_config->on_logout_redirect_cookie_regexp->re_nsub + 1 != NUM_SUBS) ) {
		dir_config->on_logout_redirect_cookie_regexp = NULL;
	}
}

static int check_logout_redirect_cookie(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	const char *cookie_name = dir_config->on_logout_redirect_cookie
					? dir_config->on_logout_redirect_cookie
					: "OPENIAM_WEBAPP_LOGOUT";
	if ( dir_config->on_logout_redirect_cookie_regexp == NULL) {
		set_and_comp_redirect_regexp(dir_config, r->pool, cookie_name);
	}
	if ( dir_config->on_logout_redirect_cookie_regexp == NULL) {
		return 0;
	}

	const char *cookies = apr_table_get(r->headers_in, "Cookie");
	char *cookieval = NULL;
	ap_regmatch_t regm[NUM_SUBS];
	if ( !ap_regexec(dir_config->on_logout_redirect_cookie_regexp, cookies, NUM_SUBS, regm, 0) ) {
		if ( regm[1].rm_so != -1 ) {
			cookieval = ap_pregsub(r->pool, "$1", cookies, NUM_SUBS, regm);
		}
		if ( regm[2].rm_so != -1 ) {
			cookieval = ap_pregsub(r->pool, "$2", cookies, NUM_SUBS, regm);
		}
	}
	if ( cookieval == NULL ) {
		return 0;
	}
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Cookie:%s=%s", cookie_name, cookieval);
	}
	return strcasecmp(cookieval, "true") == 0;
}

static void set_logout_redirect_cookie(request_rec *r, char *value)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	const char *cookie_name = dir_config->on_logout_redirect_cookie
					? dir_config->on_logout_redirect_cookie
					: "OPENIAM_WEBAPP_LOGOUT";
	const char *cookie_value = create_set_cookie(r, apr_pstrcat(r->pool, cookie_name, "=", value, NULL));
	apr_table_addn(r->err_headers_out, "Set-Cookie", cookie_value);
	//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Set-Cookie:%s", cookie_value);
}

static int iam_authn_hook_check_user_id(request_rec *r)
{
	apr_status_t ret;

	char *user_id    = NULL;
	char *principal  = NULL;
	char *token      = NULL;
	char *token_type = NULL;
	char *extra_data = NULL;
	char *challenge_response_flag = NULL;
	char *cookie     = NULL;
	char *new_cookie = NULL; 

	char *expiration_time   = NULL;
	char *create_time       = NULL;
	char *expire_in_ms      = NULL;

	char *server_url        = NULL;
	//char *target_server_url = NULL;

	apr_time_t time_create = 0;
	apr_time_t time_diff;
	apr_time_t time_expire;
	apr_time_t time_now = 0;
	apr_time_t expire_diff = 0;

	int auth_token_expired = 0;

	/* 1) check that authentication is enabled in proxy configs for that URL */
	if ( !ap_some_auth_required(r) ) {
		return DECLINED;
	}
	const char *current_auth = ap_auth_type(r);
	if ( current_auth == NULL ) {
		return DECLINED;
	}
	if ( strcasecmp(current_auth, AUTH_TYPE_OPENIAM) != 0 &&
	     strcasecmp(current_auth, AUTH_TYPE_OPENIAM_OLD) != 0 &&
	     strcasecmp(current_auth, AUTH_TYPE_OPENIAM_NOAUTH) != 0 ) {
		return DECLINED;
	}

	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);


	if ( dir_config->under_construction_redirect && (strcasecmp(dir_config->under_construction_redirect, r->uri ) == 0) ) {
		request_config->no_auth = 1;
		openiam_set_request_noauth(r);
		if ( dir_config->under_construction_backend ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "under construction proxied to: %s", dir_config->under_construction_backend);
			return reverse_proxy_to(r, dir_config->under_construction_backend);
		}
		if ( request_config->no_auth ) {
			openiam_set_request_noauth(r);
		}
		return OK;
	}

	if ( dir_config->under_construction_redirect ) {
		if ( !skip_under_construction(r) ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "redirected to under construction absolute url: %s", dir_config->under_construction_redirect);
			}
			apr_table_setn(r->headers_out, "Location", dir_config->under_construction_redirect);
			return HTTP_MOVED_TEMPORARILY;
		}
	}

	/* disable for excluded URIs */
	if ( is_excluded(r) ) {
		return OK;
	}


	/* 2) check redirects */

	char* redirect = (char*)is_redirected_before_auth(r);
	if ( redirect ) {
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "redirect before auth to: %s", redirect);
		}
		apr_table_setn(r->headers_out, "Location", redirect);
		return HTTP_MOVED_TEMPORARILY;
	}

	redirect = (char*)is_redirected(r);
	if ( redirect ) {
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "store new location in request data: %s", redirect);
		}
		request_config->redirected = redirect;
	}

	const char* request_url = ap_construct_url(r->pool, iam_encode_uri(r->pool, r->uri), r);
	const char* request_url_for_xml = iam_xml_encode_uri(r->pool, ap_construct_url(r->pool, r->unparsed_uri, r));

	/* 3) check no authentication needed for that url: */
	/* 3.1) check no authentication list */
	if ( dir_config->is_verbose )
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "checking NoAuthList");

	map_rec* exclude = is_excluded_from_auth(r);
	if ( exclude ) {
		request_config->no_auth = 1;
		openiam_set_request_noauth(r);

		/* it is not only skipped but also mapped to backend server */
		request_config->backend_url = exclude->backend
						? exclude->backend 
						: ( dir_config->ui_server_name 
							? dir_config->ui_server_name 
							: dir_config->esb_server_name );

		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "excluded uri %s in NoAuthList. backend is %s", r->uri, exclude->backend);
		}
	} else {
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "uri %s not in NoAuthList", r->uri);
		}
	}

	if ( request_config->no_auth ) {
		openiam_set_request_noauth(r);

		apr_status_t federation_ret = api_federate_proxy_uri(r, NULL, request_url_for_xml, NULL, &server_url);
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "federation(noauth) returns %d", federation_ret);
		}
		if ( federation_ret != APR_SUCCESS ) {
			/* returns OK anyway */
			return OK;
		}
		if ( request_config->backend_url == NULL ) { 
			/* do not overwrite, if it is set previously */
			request_config->backend_url = server_url;
		}
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "server url from federation(noauth) = %s", server_url);
		}
	
		if ( federation_ret == IAM_REDIRECTED ) {
			return HTTP_MOVED_TEMPORARILY;
		}
		return OK; /* continue processing at Authz function */
	}

	/* 4) check cookie configs and keys */
	if ( dir_config->auth_cookie_regexp == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OPENIAM_CookieName not set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "key size is %d", dir_config->evp_key_length);
	}
	if ( dir_config->evp_key_length == 0 ) {
		ret = api_get_private_key(r);
		if ( ret != APR_SUCCESS ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "getting key failed.");
		}
	}

	/* 4.1) read auth cookie */
	cookie = read_cookie(r);
	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "cookie:%s", cookie);
	}

	if ( cookie ) {
		if ( dir_config->evp_key_length ) {
			cookie = iam_decrypt_cookie(r, cookie);
			if ( dir_config->is_debug_cookies ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "decrypted cookie:%s", cookie);
			}
		} else {
			cookie = NULL;
		}
	}

	/* 4.2) parse cookie */
	if ( cookie ) {
		extra_data = NULL;
		challenge_response_flag = NULL;
		parse_cookie_3(r->pool, cookie, &user_id, &principal, &token, &token_type, &expire_in_ms);

		if ( dir_config->is_debug_cookies ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "user_id=%s principal=%s token=%s token_type=%s extra_data=%s challenge_response_flag=%s expire_in_ms=%s",
					user_id, principal, token, token_type, extra_data, challenge_response_flag, expire_in_ms);
		}

		if ( expire_in_ms ) {
			/* first check expire_in ms */
			const apr_int64_t ms_expired = apr_atoi64(expire_in_ms);
			const apr_int64_t ms_now     = apr_time_as_msec(apr_time_now());
			if ( dir_config->is_debug_cookies ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "\n\t now.:%ld\n\t end at:%ld ", ms_now, ms_expired);
			}

			if ( ms_now >= ms_expired ) {
				if ( dir_config->is_debug_cookies ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "user_id:%s principal:%s cookie expired", user_id, principal);
				}

				auth_token_expired = 1;
				user_id = NULL;
				token = NULL;
			}
		} else {
			if ( dir_config->is_debug_cookies ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "user_id:%s principal:%s expire not set in cookie. possible need to upgrade openiam mod_iam_authn module", user_id, principal);
			}

			/* fail. we want cookie with expired in ms field, but there no such field. delete all and go to login page.*/
			user_id = NULL;
			token = NULL;
		}

		/* checking that token is valid */
		if ( user_id && principal && token && token_type ) {
			if ( dir_config->is_debug_cookies ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "user_id:%s principal:%s token:%s token_type:%s expire:%s", user_id, principal, token, token_type, expire_in_ms);
			}
			int exists_in_cache = 0;
			int need_to_store_in_cache = 0;
			char *cache_key_name = NULL;

			iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);

#ifdef DB_CACHE
			if ( server_config->db_esb_caching ) {
				cache_key_name = iam_pstrcat(r->pool, user_id, "|", principal, "|", token, "|", token_type, NULL);
				if ( server_config->db_tokens == NULL ) {
					if ( server_config->db_env == NULL ) {
						server_config->db_env = openiam_db_init(r->server->process->pool, server_config->db_path, 0, server_config->db_mutex_count);
						if ( server_config->is_dump_caching ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "init db env");
						}
					}
					if ( server_config->db_env ) {
						server_config->db_tokens = openiam_db_open(server_config->db_env, "tokens", server_config->db_sync_after_commit);
						if ( server_config->is_dump_caching ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "init tokens db");
						}
					} else {
						if ( server_config->is_dump_caching ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "env is null");
						}
					}
				}
				if ( server_config->db_tokens ) {
					if ( server_config->is_dump_caching ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "lookup key %s in esb cache", cache_key_name);
					}
					apr_status_t ret = openiam_cache_get_time(server_config->db_tokens, cache_key_name, &expire_diff, r->pool);
					if ( ret == APR_SUCCESS ) {
						exists_in_cache = (expire_diff > 0);
						if ( server_config->is_dump_caching ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "found token %s for user_id=%s in cache (%d) expire_diff=%ld", cache_key_name, user_id, exists_in_cache, expire_diff);
						}
					} else {
						if ( server_config->is_dump_caching ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't find token %s for user_id=%s in cache", cache_key_name, user_id);
						}
					}
				} else {
					if ( server_config->is_dump_caching ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "tokens db is null");
					}
				}
			}
#endif

#ifdef SHARED_CACHE
			if ( !exists_in_cache && server_config->shared_esb_caching ) {
				cache_key_name = iam_pstrcat(r->pool, user_id, "|", principal, "|", token, "|", token_type, NULL);
				if ( server_config->tokens_sc == NULL ) {
					server_config->tokens_sc = openiam_shm_cache_init(
							r->server->process->pool, server_config->shared_size,
							server_config->shared_sync_time, server_config->is_dump_caching,
							server_config->shared_cleanup);
					if ( server_config->tokens_sc == NULL ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't init tokens shm cache");
					}
				}

				if ( server_config->tokens_sc ) {
					if ( server_config->is_dump_caching ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE lookup token %s in shm cache", cache_key_name);
					}
					exists_in_cache = openiam_shm_cache_token_exists(server_config->tokens_sc, cache_key_name, r->pool);
				}

				if ( exists_in_cache ) {
					expire_diff = apr_time_from_sec(30*60); /* esb always returns auth tokens that valid for 30 min */
					apr_atomic_inc32(&server_config->tokens_shared_hit);
					if ( server_config->is_dump_caching ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE found cached federation response for token=%s", cache_key_name);
					}
				} else {
					openiam_shm_cache_unset(server_config->tokens_sc, cache_key_name);
					need_to_store_in_cache = 1;
					apr_atomic_inc32(&server_config->tokens_shared_miss);
					if ( server_config->is_dump_caching ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE can't find cached federation response for token=%s", cache_key_name);
					}
				}

				if ( server_config->is_dump_caching ) {
					int hit  = apr_atomic_read32(&server_config->tokens_shared_hit);
					int miss = apr_atomic_read32(&server_config->tokens_shared_miss);
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE(hit %u/ miss %u) key=%s server=%d", hit, miss, cache_key_name, getpid());
				}
			}
#endif

			if ( exists_in_cache ) {
				time_expire  = apr_time_now() + expire_diff;
				expire_in_ms = apr_off_t_toa(r->pool, apr_time_as_msec(time_expire));
				ret = APR_SUCCESS;
				if ( server_config->is_dump_caching ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE exists in cache user_id:%s principal:%s token:%s token_type:%s expire:%s", user_id, principal, token, token_type, expire_in_ms);
				}
			} else {
				ret = api_renew_token_xml(r,
						&principal,
						&token,
						&token_type,
						&expiration_time,
						&create_time,
						&user_id);
				if ( ret == APR_SUCCESS ) {
					if ( dir_config->max_time_difference > 0 ) {
						/* check that time on ESB is synchronized with proxy */
						time_now    = apr_time_now();
						time_create = convert_date_from_soap_to_apr_time(create_time);
						time_diff   = apr_time_as_msec(abs(time_now - time_create));

						if ( dir_config->is_debug_cookies ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "ESB create time =%s ESB expire time = %s", create_time, expiration_time);
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "time_create=%ld time_now=%ld time_diff=%ld", time_create, time_now, time_diff);
						}

						if ( time_diff > dir_config->max_time_difference ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "time on proxy and ESB differ %s ms. Allowed %d ms difference", apr_off_t_toa(r->pool, time_diff), dir_config->max_time_difference);
							user_id = NULL;
							token   = NULL;
						} else {
							if ( dir_config->is_debug_cookies ) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "time diff with ESB=%ld", time_diff);
							}
						}
					}

					time_expire  = convert_date_from_soap_to_apr_time(expiration_time);
					expire_in_ms = apr_off_t_toa(r->pool, apr_time_as_msec(time_expire));
					expire_diff  = (time_expire - time_now);
					expire_diff  = expire_diff + 10000 - expire_diff % 10000;
					//expire_in_ms = apr_off_t_toa(r->pool, apr_time_as_msec(apr_time_now()) + 1800000);
					if ( dir_config->is_debug_cookies ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "creation time from ESB=%s expiration time from ESB=%s set expire_in_ms in cookie=%s expire_diff=%ld",
								create_time, expiration_time, expire_in_ms, expire_diff);
					}

#ifdef DB_CACHE
					if ( server_config->db_esb_caching && user_id && token && expire_diff && need_to_store_in_cache) {
						if ( server_config->db_tokens ) {
							cache_key_name = iam_pstrcat(r->pool, user_id, "|", principal, "|", token, "|", token_type, NULL);
							apr_status_t ret = openiam_cache_set_time(server_config->db_tokens, cache_key_name, expire_diff, server_config->tokens_expiration_time, r->pool);
							if ( server_config->is_dump_caching ) {
								if ( ret == APR_SUCCESS ) {
									ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "store token %s for user_id=%s in cache readed_expire_diff=%ld", cache_key_name, user_id, expire_diff);
								} else {
									ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't store token %s for user_id=%s in cache", cache_key_name, user_id);
								}
							}
						}
					}
#endif

#ifdef SHARED_CACHE
					if ( server_config->shared_esb_caching && user_id && token && expire_diff && need_to_store_in_cache) {
						if ( server_config->tokens_sc ) {
							cache_key_name = iam_pstrcat(r->pool, user_id, "|", principal, "|", token, "|", token_type, NULL);
							apr_status_t ret = openiam_shm_cache_set_token(server_config->tokens_sc, cache_key_name, apr_time_now() + server_config->tokens_expiration_time);
							if ( server_config->is_dump_caching ) {
								if ( ret == APR_SUCCESS ) {
									ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE store token for %s", cache_key_name);
								} else {
									ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "TOKENS_CACHE can't store token for %s", cache_key_name);
								}
							}
						}
					}
#endif

				}
			}
			if ( ret == APR_SUCCESS ) {
				if ( user_id && principal && token && token_type && expire_in_ms ) {
					new_cookie = create_cookie_from_id_and_token_3(r->pool, user_id, principal, token, token_type, expire_in_ms);

					if ( dir_config->is_debug_cookies ) {
						ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "create_cookie_from_id_and_token returned cookie:%s", new_cookie);
					}
				}
			}
		}
	}


	/*  here we can have new unencrypted (plain) cookie or not.
	       if not: check uri parameters */
	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "authentication: user_id:%s principal:%s new_cookie:%s", user_id, principal, new_cookie);
	}
	if ( user_id == NULL || new_cookie == NULL ) {
		if ( r->args ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "r->args:%s ", r->args);
			}
			apr_table_t* arguments = iam_request_arguments(r);

			const char *userid = apr_table_get(arguments, "userid");
			if ( userid == NULL ) {
				userid = apr_table_get(arguments, "principal");
			}
			const char *password  = apr_table_get(arguments, "pswd");
			if ( password == NULL ) {
				password = apr_table_get(arguments, "psswd");
			}
			if ( password == NULL ) {
				password = apr_table_get(arguments, "password");
			}
			if ( userid ) {
				userid = iam_unescape_uri(r->pool, userid);
			}
			if ( password ) {
				password = iam_unescape_uri(r->pool, password);
			}
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "api_login: userid:%s password:%s", userid, password);
			}
			apr_status_t ret = api_login(r, userid, password,
							&token_type, &token, &principal, &user_id, &expiration_time);
			if ( ret == APR_SUCCESS ) {
				/* good login. creating token and cookie */
				r->args = NULL;
				ret = api_cookie_data_from_principal(r, principal, request_url,
								     &token_type, &token, &principal, &user_id, &expiration_time);
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "login: user_id:%s principal:%s token:%s token_type:%s expire:%s", user_id, principal, token, token_type, expiration_time);
#if (DEBUG_DUMP_COOKIE_TIME)
					iam_debug_dump_time(r, "time_expire= ", time_expire);
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "expire_time=%s", expiration_time);
#endif
				}
				if ( user_id && principal && token && token_type ) {
					time_expire = convert_date_from_soap_to_apr_time(expiration_time);
					expire_in_ms = apr_off_t_toa(r->pool, apr_time_as_msec(time_expire));
					new_cookie = create_cookie_from_id_and_token_3(r->pool, user_id, principal, token, token_type, expire_in_ms);
				}
			}
		}
	}

	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "call federation for %s and user_id %s (principal %s)", request_url, user_id, principal);
	}
	apr_status_t federation_ret = api_federate_proxy_uri(r, user_id, request_url_for_xml, NULL, &server_url);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "federation ret %d", federation_ret);
	}
	if ( federation_ret != APR_SUCCESS ) {
		user_id = NULL;
		new_cookie = NULL;
		request_config->user_id = NULL;
	}
	request_config->backend_url = server_url;
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "server url from federation = %s", server_url);
	}
	
	if ( federation_ret == IAM_REDIRECTED ) {
		return HTTP_MOVED_TEMPORARILY;
	} else if ( federation_ret == APR_SUCCESS ) {
		if ( request_config->no_auth ) {
			openiam_set_request_noauth(r);
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "uri %s have NOAUTH authentication", r->uri);
			}
			return OK;
		}
	} else if ( federation_ret != APR_SUCCESS ) {
		/*  here we can have new unencrypted (plain) cookie or not.
		       if not: check kerberos authentication if enabled */

		if ( user_id == NULL || new_cookie == NULL ) {
			/* 5) no cookie. auth needed. trying certs, if enabled */

			if ( dir_config->is_dump_requests && !request_config->no_auth ) {
				iam_debug_dump_request(r, "DUMP REQUEST BEFORE KERBEROS OR CERT AUTH: ");
			}

			int need_to_construct_new_cookie = 0;

			if ( request_config->cert_auth ) {
				if ( dir_config->is_debug_cert ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "uri %s trying cert authentication", r->uri);
				}

				char* cert_pem = NULL;
				char* json = NULL;
				ret = openiam_read_cert(r, &cert_pem);
				if ( cert_pem && strlen(cert_pem) == 0 ) {
					cert_pem = NULL;
				}
				if ( ret != APR_SUCCESS || cert_pem == NULL ) {
					if ( dir_config->read_client_cert_from_header ) {
						cert_pem = apr_table_get(r->headers_in, dir_config->client_cert_header_name ? dir_config->client_cert_header_name : s_client_cert_header);
					}
				}
				if ( dir_config->is_debug_cert && cert_pem ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "client certificate is %s", cert_pem);
				}
				if ( cert_pem != NULL ) {
					cert_pem = openiam_fix_special_inplace(r->pool, cert_pem);
					if ( dir_config->is_debug_cert && cert_pem ) {
						ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "client certificate after fixup is %s", cert_pem);
					}
					ret = api_send_cert_to_esb(r, cert_pem, r->uri, r->method, &json);
					if ( ret != APR_SUCCESS ) {
						if ( dir_config->is_debug_cert ) {
							ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "unable to authenticate to uri %s, using certificate", r->uri);
						}
					} else {
						char *cert_principal = NULL;
						char *error_text = NULL;
						ret = openiam_parse_cert_response(r->pool, json, &cert_principal, &error_text);
						if ( ret == APR_SUCCESS && cert_principal )
						{
							if ( dir_config->is_debug_cert ) {
								ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "SUCCESSFULL authentication using certificate for %s", cert_principal ? cert_principal : "(null)");
							}
							r->user = cert_principal;
							need_to_construct_new_cookie = 1;
							if ( dir_config->do_not_generate_cookie_for_cert_auth )
							{
								// use cookie only for login to backend. do not propagate it
								apr_table_setn(r->notes, NOTE_CLEAN_AUTH_INFO, "1");
							}
						}
						else
						{
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "FAILED attempt to authenticate using certificate for uri %s", r->uri);
							if ( error_text ) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Certificate authentication error: %s", error_text);
							}
						}
					}
				}
			}

			/* 5) no cookie. then trying kerberos, if enabled */


			if ( dir_config->krb_enabled && request_config->kerb_auth ) { /* process only if kerberos configured and URI pattern have kerberos enabled */
				ret = kerb_authenticate_user(r);
				if ( ret == OK ) {
					need_to_construct_new_cookie = 1;
				} else if ( ret != DECLINED ) {
					return ret;
				}
			}

			if ( need_to_construct_new_cookie ) {
				ret = api_cookie_data_from_principal(r, r->user, request_url,
							     &token_type, &token, &principal, &user_id, &expiration_time);
				if ( dir_config->is_debug_kerb ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "kerberos or cert: user_id:%s principal:%s token:%s token_type:%s expire:%s", user_id, principal, token, token_type, expiration_time);
				}
				if ( user_id && principal && token && token_type ) {
					time_expire = convert_date_from_soap_to_apr_time(expiration_time);
					expire_in_ms = apr_off_t_toa(r->pool, apr_time_as_msec(time_expire));
					new_cookie = create_cookie_from_id_and_token_3(r->pool, user_id, principal, token, token_type, expire_in_ms);
				}
			}

		}
	}

	/* 6) encrypt new cookie */
	if ( new_cookie ) {
		if (  dir_config->evp_key && dir_config->evp_key_length ) {
			new_cookie = iam_encrypt_cookie(r, new_cookie);
			if ( dir_config->is_debug_cookies ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "new encrypted cookie:%s", new_cookie);
			}
		} else {
			 /* no key - no cookie. dot */
			new_cookie = NULL;
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "can't encrypt cookie. no key available");
		}
	}

	/* 7) set new cookie */
	if ( dir_config->is_debug_cookies ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "new cookie is:%s", new_cookie);
	}

	apr_table_setn(r->headers_out, s_auth_header, new_cookie ? new_cookie : "");

	if ( new_cookie ) {
		char *cookie_header = create_auth_cookie(r, new_cookie);
		if ( cookie_header ) {
			apr_table_setn(r->headers_out, "Set-Cookie", cookie_header);
			if ( cookie == NULL ) {
				if ( dir_config->is_debug_cookies ) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "add missing cookie");
				}
				const char* current_cookies = apr_table_get(r->headers_in, "Cookie");
				if ( current_cookies ) {
					apr_table_setn(r->headers_in,  "Cookie", apr_pstrcat(r->pool, current_cookies, ";", cookie_header, NULL));
				} else {
					apr_table_setn(r->headers_in,  "Cookie", cookie_header);
				}
			}
		}
		request_config->user_id = apr_pstrdup(r->pool, user_id);
		r->user = apr_pstrdup(r->pool, principal);
		r->ap_auth_type = (char*)current_auth;
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "valid authentication for user: %s %s", r->user,  r->ap_auth_type);
		}

		if ( dir_config->is_dump_requests && !request_config->no_auth ) {
			iam_debug_dump_request(r, "DUMP REQUEST: ");
		}

		/* special handling for /link uri */
		if ( dir_config->internal_leave_link ) {
			if ( strcasecmp(r->uri, dir_config->internal_leave_link) == 0 ) {
				set_logout_redirect_cookie(r, "true");
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "set logout cookie to true");
				}
				char *url = iam_unescape_uri(r->pool, r->args);
				apr_table_setn(r->err_headers_out, "Refresh", apr_pstrcat(r->pool, "0;url=", url, NULL));
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "refresh to %s", url);
				}
				return OK;
			}
		}

		return OK;
	}

	/* 8) last check doesn't help. redirecting to login page */

	if ( dir_config->login_url == NULL ) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "OPENIAM_LoginUrl not set");
		return HTTP_INTERNAL_SERVER_ERROR;
	} else {
		const char *request_url = dir_config->on_auth_redirect ? dir_config->on_auth_redirect : r->unparsed_uri;
		if ( request_url ) {
			request_url = iam_escape_uri(r->pool, request_url);
		}
		char *server_login_url = NULL;
		//iam_authn_server_config_rec *server_config = ap_get_module_config(r->server->module_config, &iam_authn_module);
		char *redirect_overwrite = (char*)login_redirect(r);
		if ( redirect_overwrite ) {
			server_login_url = apr_pstrcat(r->pool, redirect_overwrite, dir_config->login_url, NULL);
		} else {
			server_login_url = ap_construct_url(r->pool, dir_config->login_url, r);
		}
		const char *redirect_url =  apr_pstrcat(r->pool, server_login_url, dir_config->postback_param, request_url, NULL);
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "redirected to: %s", redirect_url);
		}
		set_logout_redirect_cookie(r, "unset");
		if (auth_token_expired) {
			set_expired_headers(r);
		} else {
			set_missing_auth_headers(r);
		}
		apr_table_setn(r->headers_out, "Location", redirect_url);
	}
	return HTTP_MOVED_TEMPORARILY;

	/* nothing helps */

	return HTTP_UNAUTHORIZED;
}

/* KERBEROS AUTH HELPER */

/* AUTHORIZATION ********************************************************************************************************************************************* */

static char* url_with_proxy_preffix(request_rec *r, const char *server_url) {
	int is_https = 0;
	int is_http  = 0;

	if ( strncasecmp(server_url, "http", 4) == 0 ) {
		const char* s = server_url + 4;
		is_https = strncasecmp(s, "s://", 4) == 0;
		if ( !is_https ) {
			is_http  = strncasecmp(s, "://",  3)  == 0;
		}
	}
	return apr_pstrcat(r->pool, (( !is_http && ! is_https )
						? "proxy:http://"
						: "proxy:"), server_url, r->uri, NULL);
}

static void reverse_proxy_fix_logout_redirect(request_rec* r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	// redirect only if auth cookie present
	if ( dir_config->logout_url && (strcasecmp(r->uri, dir_config->logout_url) == 0)) {
		set_logout_headers(r);

		if ( dir_config->on_logout_redirect ) {
			char *cookie = read_cookie(r);
//			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, r->server, "reverse_proxy_fix_logout_redirect cookie: %s", cookie);
/*
			if ( cookie ) {
				if ( dir_config->evp_key_length ) {
					cookie = iam_decrypt_cookie(r, cookie);
				} else {
					cookie = NULL;
				}
			}
*/
			if ( cookie ) {
				if ( check_logout_redirect_cookie(r) ) {
					set_logout_redirect_cookie(r, "unset");
					apr_table_setn(r->err_headers_out, "Refresh", apr_pstrcat(r->pool, "0;url=", dir_config->on_logout_redirect, NULL));
				}
			}
		}
	}
}


static int iam_authz_hook_check_auth(request_rec *r)
{
	const char* server_url = NULL;
	char* target_server_url = NULL;
	const char *request_url;

	if ( !ap_some_auth_required(r) ) {
		return DECLINED;
	}

	/* disable for excluded URIs */
	if ( is_excluded(r) ) {
		return DECLINED;
	}

	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);

	if ( request_config->redirected ) {
		char *redirect = request_config->redirected;
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "redirected to: %s", redirect);
		}
		apr_table_setn(r->headers_out, "Location", redirect);
		return HTTP_MOVED_TEMPORARILY;
	}

	server_url = request_config->backend_url;
	target_server_url = get_target_server_override(r);
	if ( target_server_url ) { /* will override value from ESB */
		server_url = target_server_url;
	}
	if ( strcasecmp(server_url, "localhost") == 0 ) {
		server_url = NULL;
	}

	/* turn off reverse proxying for generated content */
	char *str_generate_form_post = apr_table_get(r->notes, NOTE_GENERATE_FORM_POST);
	if ( str_generate_form_post && strcmp(str_generate_form_post, "1") == 0 ) {
		server_url = NULL;
	}

	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "server url = %s (was %s)", server_url, request_config->backend_url);
	}

	if ( request_config->no_auth ) {
		reverse_proxy_fix_logout_redirect(r);
		if ( server_url == NULL ) {
			/*if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "skip authorization for %s", r->uri);
			}*/
			return OK;
		} else {
			/*if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "skip authorization for %s. proxied to %s", r->uri, request_config->backend_url);
			}*/
			return reverse_proxy_to(r, url_with_proxy_preffix(r, server_url));
		}
	}

	const char *current_auth = ap_auth_type(r);
	if ( current_auth == NULL ) {
		return DECLINED;
	}
	if ( strcasecmp(current_auth, AUTH_TYPE_OPENIAM) != 0 &&
	     strcasecmp(current_auth, AUTH_TYPE_OPENIAM_OLD) != 0 &&
	     strcasecmp(current_auth, AUTH_TYPE_OPENIAM_NOAUTH) != 0 ) {
		return DECLINED;
	}

	request_url = ap_construct_url(r->pool, iam_encode_uri(r->pool, r->uri), r);
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "request url %s user %s(%s) authtype %s", request_url, r->user, request_config->user_id, r->ap_auth_type);
	}

	if ( request_config->user_id == NULL
			|| r->ap_auth_type == NULL 
			|| r->user == NULL ) {
		if ( dir_config->is_verbose ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "not authenticated");
		}
		if ( dir_config->on_fail_redirect ) {
			apr_table_setn(r->headers_out, "Location", dir_config->on_fail_redirect);
			return HTTP_MOVED_TEMPORARILY;
		}
		return HTTP_UNAUTHORIZED;
	}

	if ( server_url ) {
		return reverse_proxy_to(r, url_with_proxy_preffix(r, server_url));
	} else {
		return OK;
	}
}

/* MOD_HTML FILTER ********************************************************************************************************************/


static apr_status_t iam_fix_content_filter(ap_filter_t* f, apr_bucket_brigade* bb)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(f->r->per_dir_config, &iam_authn_module);
	apr_status_t ret = iam_substitute(f, bb, dir_config->patterns);
	if ( ret != APR_SUCCESS ) {
		return ret;
	}
	return ap_pass_brigade(f->next, bb);
}


/* HEADERS FIXUP FILTER *************************************************************************************************************/

static char* fix_cookie_domain(request_rec* r, char *str, const char* cookie_name, const char* fake)
{
	apr_size_t len = strlen(str);
	apr_size_t doffs;
	apr_size_t l1;
	apr_size_t l2;
	apr_size_t diff;
	char* ret = str;
	char* domainp = strcasestr(str, s_domain);
	char* domaine;
	if ( domainp != NULL ) {
		doffs = domainp - str;
		domaine = ap_strchr_c(domainp, ';');
		if ( domaine == NULL ) {
			l1 = strlen(domainp);
			domaine = domainp + l1;
		} else {
			l1 = domaine - domainp;
		}
		l2 = strlen(fake);
		diff = l2 + sizeof(s_domain) - l1; /* FIXME */
		if ( diff > 0 ) {
			ret = apr_pcalloc(r->pool, len + diff + 1);
			memcpy(ret, str, doffs);
		}
		strcpy(ret + doffs + l2, domaine);
		memcpy(ret + doffs, fake, l2);
		return ret;
	}
	return NULL;
}


static void reverse_proxy_headers(request_rec* r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	iam_authn_request_config_rec *request_config = ap_get_module_config(r->request_config, &iam_authn_module);
	const apr_array_header_t *arr = apr_table_elts(r->headers_out);
	apr_table_entry_t  *entries   = (apr_table_entry_t *)arr->elts;
	char *value;
	const char *key;
	char *new_value;
	apr_size_t len = 0;
	int i;
/*
	if ( dir_config->is_verbose ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "static void reverse_proxy_headers(request_rec* r)");
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "DUMP REQUEST BEFORE: ralias_real=%s ralias_fake=%s", request_config->ralias_real, request_config->ralias_fake);
		iam_debug_dump_request(r, "DUMP REQUEST BEFORE: "); 
	}
*/
	if ( request_config && request_config->ralias_real && request_config->ralias_fake ) {
		for (i = 0; i < arr->nelts; i++) {
			key   = entries[i].key;
			//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "key=%s i=%i", key, i);
			if ( strcasecmp(key, s_location) == 0 || 
			     strcasecmp(key, s_content_location) == 0 ||
			     strcasecmp(key, s_uri) == 0 ||
			     strcasecmp(key, s_destination) == 0 ) {
				value = entries[i].val;
				//ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "key=%s value=%s", key, value);
				if ( len == 0 ) {
					len = strlen(request_config->ralias_real);
				}
				if ( strncasecmp(value, request_config->ralias_real, len) == 0 ) {
					if ( r->proxyreq ) {
						new_value = apr_pstrcat(r->pool, request_config->ralias_fake, value + len, NULL);
						if ( dir_config->ignore_invalid_chars_in_redirect ) {
							char* c = strpbrk(new_value, dir_config->ignore_invalid_chars_in_redirect );
							if ( dir_config->is_verbose ) {
								ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Invalid char (%s) in redirect: %s", dir_config->ignore_invalid_chars_in_redirect, new_value);
							}
							if ( c ) {
								*c = '\0';
							}
							if ( dir_config->is_verbose ) {
								ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Redirect fixed: %s", new_value);
							}
						}
						entries[i].val = new_value;
						if ( dir_config->is_verbose ) {
							ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "REPLACED WITH: %s=%s was %s real=%s fake=%s", key, new_value, value,
							request_config->ralias_real, request_config->ralias_fake);
						}
					}
				}
			} else if ( strcasecmp(key, s_set_cookie) == 0 ) {
				value = entries[i].val;
				if ( dir_config->is_verbose ) {
					ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Set-Cookie DEBUG: %s=%s, %d", key, value, i);
				}
				if ( dir_config->auth_cookie_name ) {
					new_value = fix_cookie_domain(r, value, dir_config->auth_cookie_name, request_config->cookie_fake);
					if ( new_value ) {
						if ( r->proxyreq ) {
							if ( dir_config->is_verbose ) {
								ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "new cookie: %s", new_value);
							}
							entries[i].val = (char*)new_value;
						}
					}
				}
			}
		}
	}
}

static void set_headers(request_rec* r)
{
	const char* headers = apr_table_get(r->notes, NOTE_PROPAGATE_HEADERS);
	while ( headers && *headers ) {
		char* next = strchr(headers, ';');
		const char* key = headers;
		if ( next ) {
			*next++ = '\0';
		}
		const char* value =  apr_table_get(r->headers_in, key);
		if ( value ) {
			apr_table_setn(r->headers_out, key, value);
		}
		headers = next;
	}
}

static void set_auth_header(request_rec* r)
{
	const char *auth_token = read_out_cookie(r);
	apr_table_set(r->headers_out, s_auth_header, auth_token ? auth_token : "");
}

static void set_cookies(request_rec* r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->logout_url && dir_config->on_logout_redirect && (strcasecmp(r->uri, dir_config->logout_url) == 0)) {
		char *cookie = read_cookie(r);
		if ( cookie ) {
			set_logout_redirect_cookie(r, "unset");
		}
	}

	const char* cookies = apr_table_get(r->notes, NOTE_PROPAGATE_COOKIES);
	while ( cookies && *cookies ) {
		char* next = strchr(cookies, ';');
		const char* cookie = cookies;
		if ( next ) {
			*next++ = '\0';
		}
		if ( cookie && *cookie) {
			const char* value = create_set_cookie(r, cookie);
			apr_table_addn(r->headers_out, "Set-Cookie", value);
		}
		cookies = next;
	}
}

static void clean_auth_info_and_cookie(request_rec *r)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);

	apr_table_unset(r->headers_out, "x-openiam-auth-token");
	apr_table_unset(r->err_headers_out, "x-openiam-auth-token");

	if ( !dir_config->auth_cookie_name )
		return;

	const apr_array_header_t *arr = apr_table_elts(r->headers_out);
	apr_table_entry_t *entries   = (apr_table_entry_t *)arr->elts;

	int i;
	for (i = 0; i < arr->nelts; i++) {
		char *key = entries[i].key;
		if ( strcasecmp(key, s_set_cookie) == 0 ) {
			char *value = entries[i].val;
			if ( value == NULL )
				continue;

			char *name_end = strchr(value, '=');
			if ( name_end ) {
				size_t len = name_end - value;
				if ( strncasecmp(dir_config->auth_cookie_name, value, len) == 0 ) {
					if ( dir_config->is_debug_cert ) {
						ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "found %s in response. cleaning", value);
					}
					*value = '\0'; // unset it.
				}
			}
		}
	}
}

static apr_status_t iam_headers_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(f->r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_debug_filters ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "static apr_status_t iam_headers_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)");
	}

	/* http://jira.openiam.com/browse/AM-425 disable gzip after proxying. this can cause errors on https then content actually not html but json */

	if ( !( f->r->content_type && ( strncasecmp(f->r->content_type, "application/java-archive", 24) == 0) ) ) {
		apr_table_set(f->r->subprocess_env, "no-gzip", "1");
	}

	/* copy headers_in to headers_out */

	reverse_proxy_headers(f->r);
	set_headers(f->r);
	set_cookies(f->r);
	const char *clean_auth_info = apr_table_get(f->r->notes, NOTE_CLEAN_AUTH_INFO);
	if ( clean_auth_info && strcmp(clean_auth_info, "1") == 0 )
	{
		if ( dir_config->is_debug_cert ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "skip setting authentication cookie in response");
		}
		clean_auth_info_and_cookie(f->r);
	}
	else
	{
		set_auth_header(f->r);
	}

#if (DEBUG_DUMP_PATTERNS)
	if ( dir_config->is_dump_requests ) {
		iam_authn_request_config_rec *request_config = ap_get_module_config(f->r->request_config, &iam_authn_module);
		if ( ! request_config->no_auth ) {
			iam_debug_dump_request(f->r, "DUMP AFTER PROPAGATION: ");
		}
	}
#endif

	ap_remove_output_filter(f);
	return ap_pass_brigade(f->next, bb);
}

/* BOTH OUTPUT FILTERS *************************************************************************************************************/

static void iam_insert_output_filters(request_rec *r)
{
	/* disable for excluded URIs */
	if ( is_excluded(r) ) {
		return;
	}

	/* disable output filters for generated content */
	char *str_generate_form_post = apr_table_get(r->notes, NOTE_GENERATE_FORM_POST);
	if ( str_generate_form_post && strcmp(str_generate_form_post, "1") == 0 ) {
		return;
	}

	iam_authn_dir_config_rec *dir_config = ap_get_module_config(r->per_dir_config, &iam_authn_module);
	if ( dir_config->is_debug_filters ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "iam_insert_output_filters(request_rec *r)");
	}

	if ( r->proxyreq == PROXYREQ_REVERSE ) {
		ap_add_output_filter(s_fix_headers_filter_name, NULL, r, r->connection);
		if ( dir_config->is_debug_filters ) {
			ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "ap_add_output_filter(s_fix_headers_filter_name, NULL, r, r->connection);");
		}
		if ( !r->content_type || ( 
		    ( strncasecmp(r->content_type, "text/html", 9) == 0) ||
		    ( strncasecmp(r->content_type, "text/xml", 8) == 0) ||
		    ( strncasecmp(r->content_type, "text/x-jsrender", 15) == 0) ||
		    ( strncasecmp(r->content_type, "application/xhtml+xml", 21) == 0 ) || 
		    ( strncasecmp(r->content_type, "application/javascript", 22) == 0 ) ||
		    ( strncasecmp(r->content_type, "application/x-javascript", 24) == 0 ) ||
		    ( strncasecmp(r->content_type, "text/css", 8) == 0 ) ||
		    ( strncasecmp(r->content_type, "text/javascript", 15) == 0 )) ) {
			ap_add_output_filter(s_fix_content_filter_name, NULL, r, r->connection);
		} else {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "do not fix content for content-type: %s", r->content_type);
			}
		}
	}
}

/* FORM POST FILTER *****************************************************************************************************************/

static apr_status_t iam_form_input_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
	iam_authn_dir_config_rec *dir_config = ap_get_module_config(f->r->per_dir_config, &iam_authn_module);
	apr_bucket* args_bucket = NULL;
	const char* args = apr_table_get(f->r->notes, NOTE_FORM_POST_DATA);
	int length;

	if ( args && (length = strlen(args)) ) {
		args_bucket = apr_bucket_pool_create(args, length, f->r->pool, f->c->bucket_alloc);
		if ( !APR_BRIGADE_EMPTY(bb) ) {
			apr_brigade_cleanup(bb);
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "FORM POST FILTER DEBUG: brigade was not empty");
			}
		}
		APR_BRIGADE_INSERT_HEAD(bb, args_bucket);
		if ( dir_config->is_debug_filters ) {
			if ( dir_config->is_verbose ) {
				ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->r->server, "FORM POST FILTER DEBUG. Added Content: %s", args);
			}
		}
	}
	ap_remove_input_filter(f);
	/*ap_add_output_filter(s_post_form_output_name, NULL, f->r, f->r->connection);*/
	return ap_get_brigade(f->next, bb, mode, block, readbytes);
}

/* FORM POST CONTENT GENERATOR *****************************************************************************************************************/

static int  openiam_generate_html_form_post_handler(request_rec *r)
{
	/* generate content only if special note specidied */
	char *str_generate_form_post = apr_table_get(r->notes, NOTE_GENERATE_FORM_POST);
	if ( str_generate_form_post == NULL || strcmp(str_generate_form_post, "1") != 0 ) {
		return DECLINED;
	}

	iam_authn_request_config_rec *request_config = iam_authn_get_request_config(r);

	char *server_url = request_config->backend_url;
	char *target_server_url = get_target_server_override(r);
	if ( target_server_url ) { /* will override value from ESB */
		server_url = target_server_url;
	}
	if ( strcasecmp(server_url, "localhost") == 0 ) {
		server_url = NULL;
	}

	char *original_url = NULL;
	if ( server_url ) {
		original_url = apr_pstrcat(r->pool, server_url, r->unparsed_uri, NULL);
	} else {
		original_url = ap_construct_url(r->pool, r->unparsed_uri, r);
	}

/* example:

<!DOCTYPE html>
<!--[if lte IE 8 ]> <html lang="en" class="ie"> <![endif]-->
<!--[if (gt IE 8)|!(IE)]><!--> <html lang="en"> <!--<![endif]-->
<------><head>
<script type="text/javascript">
function submitForm() {
   document.getElementById('form-login').submit();
}
</script>

</head>
<body onload="javascript:submitForm()">
<form id="form-login" name="form-login" method="post" target="_blank" action="https://somedomain.com/auth/?action=login.
<input type="hidden" name="customerpath" value="/lacoe" />
<input type="hidden" name="customerid" value="26993" />
<input type="hidden" name="username" id="username" value="XXXX" />
<input type="hidden" name="password" id="password" maxlength="250" value="XXXXX" />
<input type="hidden" name="captcha" autocomplete="off" />
<input type="hidden" value="Login" />
</form>

</body>
</html>

*/

	r->content_type = "text/html; charset=UTF-8";
	apr_table_setn(r->headers_out, "Content-Type", r->content_type);

	ap_rprintf(r, "<!DOCTYPE html>\n");
	ap_rprintf(r, "<html lang=\"en\">\n");
	ap_rprintf(r, "<head>\n");
	ap_rprintf(r, "<script type=\"text/javascript\">\n");
	ap_rprintf(r, "function submitForm() { \ndocument.getElementById('form-login').submit(); \n } \n </script>\n");
	ap_rprintf(r, "</head>\n");
	ap_rprintf(r, "<body onload=\"javascript:submitForm()\">\n");
	//ap_rprintf(r, "<body>\n");

	ap_rprintf(r, "<form id=\"form-login\" name=\"form-login\" method=\"post\" action=\"%s\">\n", original_url);

	apr_array_header_t *values = request_config->form_fields;
	int i;
	for ( i = 0; i < values->nelts - 1; i += 3 ) {
		const char* name  = ((char**)values->elts)[i];
		const char* value = ((char**)values->elts)[i+1];
		if ( name && value ) {
			ap_rprintf(r, "<input type=\"hidden\" name=\"%s\" value=\"%s\" />\n", name, value);
		}
	}
	ap_rprintf(r, "<input type=\"hidden\" value=\"Login\" />\n");
	ap_rprintf(r, "</form>\n");
	ap_rprintf(r, "</body>\n");
	ap_rprintf(r, "</html>\n");

/*
	char *html_page_buff = NULL;
	if ( read_html_page_at_url(r, original_url, &html_page_buff) != APR_SUCCESS ) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "can't get original form post");
		html_page_buff = NULL;
	}

	ap_rflush(r);
	ap_rprintf(r, "%s", html_page_buff);
	ap_rflush(r);
*/
	return OK;
}

/* CONFIG *****************************************************************************************************************/

static int iam_authn_hook_post_config(apr_pool_t *pool, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *server)
{
	void *data = NULL;
	static const char *userdata_key = "iam_authn_hook_post_config_shm_counter";
	apr_pool_userdata_get(&data, userdata_key, server->process->pool);

	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key, apr_pool_cleanup_null, server->process->pool);
		/* ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "OpenIAM module " OPENIAM_MODULE_NAME " loading."); */
	} else {
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, server, "OpenIAM module " OPENIAM_MODULE_NAME " loaded.");
	}
	return OK;
}

/* ***************************************************************************************/

static void iam_authn_hooks(apr_pool_t *p)
{
	int curl_result = curl_global_init(CURL_GLOBAL_ALL);
	/* if we continue without curl_global_init. at some point curl_easy_init called from different threads can crash our module. exiting... */

	ap_assert(curl_result == 0);

	LIBXML_TEST_VERSION;
	xmlInitParser();

#ifdef DEBUG
	ERR_load_crypto_strings();
#endif

	ap_hook_check_user_id(iam_authn_hook_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(iam_authz_hook_check_auth,     NULL, NULL, APR_HOOK_FIRST);
	ap_hook_handler(openiam_generate_html_form_post_handler, NULL, NULL, APR_HOOK_MIDDLE);

	ap_register_output_filter(s_fix_headers_filter_name,    iam_headers_output_filter, NULL, AP_FTYPE_CONTENT_SET);
	ap_register_output_filter(s_fix_content_filter_name,    iam_fix_content_filter,    NULL, AP_FTYPE_RESOURCE);

	ap_hook_insert_filter(iam_insert_output_filters,        NULL,                      NULL, APR_HOOK_LAST);

	ap_register_input_filter (s_post_form_filter_name, iam_form_input_filter,          NULL, AP_FTYPE_CONTENT_SET);
/*	ap_register_output_filter(s_post_form_output_name, iam_form_output_filter,         NULL, AP_FTYPE_CONTENT_SET); */

	ap_hook_post_config(iam_authn_hook_post_config, NULL, NULL, APR_HOOK_MIDDLE);

#ifdef SHARED_CACHE
	openiam_register_shm_hooks(p);
#endif

}

static const command_rec iam_config_cmds[] = {
	AP_INIT_TAKE1   ("OPENIAM_ServiceBaseUrl",       ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, esb_server_name),        OR_ALL, "ESB url for all web services"),
	AP_INIT_TAKE1   ("OPENIAM_OpenIAMVersion",       cmd_set_openiam_version, NULL,                                                             OR_ALL, "ESB OpenIAM version"),
	AP_INIT_TAKE1   ("OPENIAM_UIBaseUrl",            ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, ui_server_name),         OR_ALL, "Base url for all User Interface"),

	AP_INIT_TAKE1   ("OPENIAM_ServiceAuth",          ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, service_auth),           OR_ALL, "Auth Service URI"),
	AP_INIT_TAKE1   ("OPENIAM_ServiceKeyManagement", ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, service_key_management), OR_ALL, "Key Management Service URI"),
	AP_INIT_TAKE1   ("OPENIAM_ServiceFederation",    ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, service_federation),     OR_ALL, "Federation Service URI"),
	AP_INIT_TAKE1   ("OPENIAM_ServiceCert",          ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, service_cert),           OR_ALL, "Certificate identity Service URI"),

	AP_INIT_FLAG    ("OPENIAM_NoCookieForCertAuth",  ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, do_not_generate_cookie_for_cert_auth),       OR_ALL, "Check certificate on each request"),
	AP_INIT_FLAG    ("OPENIAM_ClientCertFromHeader", ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, read_client_cert_from_header),  OR_ALL, "Read client certificate from header"),
	AP_INIT_TAKE1   ("OPENIAM_ClientCertHeaderName",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, client_cert_header_name),       OR_ALL, "Client certificate heaser nane"),

	AP_INIT_TAKE1   ("OPENIAM_RProxyTimeout",        ap_set_int_slot,    (void*)APR_OFFSETOF(iam_authn_dir_config_rec, rproxy_timeout),         OR_ALL, "r-proxy timeout"),
	AP_INIT_TAKE1   ("OPENIAM_RProxyTTL",            ap_set_int_slot,    (void*)APR_OFFSETOF(iam_authn_dir_config_rec, rproxy_ttl),             OR_ALL, "r-proxy ttl"),

	AP_INIT_TAKE1   ("OPENIAM_AuthUrl",              ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, on_auth_redirect),       OR_ALL, "redirect on success form post login"),
	AP_INIT_TAKE1   ("OPENIAM_FailUrl",              ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, on_fail_redirect),       OR_ALL, "redirect on fail form post login"),
	AP_INIT_TAKE1   ("OPENIAM_ProxyPassReverse",     set_proxypass_reverse, NULL,     OR_ALL, "ProxyPassReverse equivalent"),
	AP_INIT_TAKE1   ("OPENIAM_RedirectOverwrite",    set_redirect_overwrite, NULL,     OR_ALL, "redirect to login page at this server"),
	AP_INIT_TAKE1   ("OPENIAM_LoginLocationOverwrite",    set_redirect_overwrite, NULL,     OR_ALL, "redirect to login page at this server"),
	AP_INIT_TAKE2   ("OPENIAM_LoginRedirect",        cmd_set_login_redirect, NULL,     OR_ALL, "redirect to login page at second value this server if URI equal to first value"),
	AP_INIT_TAKE3   ("OPENIAM_LoginUrl",             set_login_url,      NULL,                                                                  OR_ALL, "URLs of the login page"),
	AP_INIT_TAKE2   ("OPENIAM_LogoutUrl",            set_logout_url,     NULL,                                                                  OR_ALL, "URLs of the logout page"),
	AP_INIT_TAKE3   ("OPENIAM_LogoutRedirect",       set_logout_redirect,NULL,                                                                  OR_ALL, "redirect to this url before logout"),
	AP_INIT_TAKE1   ("OPENIAM_LogoutRedirectCookie", ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, on_logout_redirect_cookie), OR_ALL, "cookie that is used in logout redirect"),
	AP_INIT_ITERATE2("OPENIAM_SetHeadersAtExpiration",cmd_set_headers_at_expiration, NULL,                                                      OR_ALL, "set this headers then session is expired"),
	AP_INIT_ITERATE2("OPENIAM_SetHeadersAtMissingAuth",cmd_set_headers_at_missing_auth, NULL,                                                   OR_ALL, "set this headers then session autn token is missing"),
	AP_INIT_ITERATE2("OPENIAM_SetHeadersAtLogout",   cmd_set_headers_at_logout, NULL,                                                           OR_ALL, "set this headers at logout"),

	AP_INIT_TAKE1   ("OPENIAM_CookieName",           set_cookie_name,    NULL,                                                                  OR_ALL, "Name of the cookie that the apache module should check for a token"),
	AP_INIT_TAKE1   ("OPENIAM_CookieDomain",         set_cookie_domain,  NULL,                                                                  OR_ALL, "Cookie domain"),
	AP_INIT_TAKE1   ("OPENIAM_CookieSecure",         set_cookie_secure_deprecated,   NULL,       OR_ALL, "Is Cookie encrypted"),
	AP_INIT_TAKE1   ("OPENIAM_MaxTimeDifference",    ap_set_int_slot,    (void*)APR_OFFSETOF(iam_authn_dir_config_rec, max_time_difference),    OR_ALL, "If expired time in cookie differ more than that value, fix it or generate error, depend on OPENIAM_CookieFixExpireTimeIfDiffer"),
	AP_INIT_FLAG    ("OPENIAM_SendSchemeHeader",     ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_send_scheme),         OR_ALL, "Add Scheme header to each proxied request"),
	AP_INIT_FLAG    ("OPENIAM_Verbose",              ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_verbose),             OR_ALL, "Verbose logs"),
	AP_INIT_TAKE1   ("OPENIAM_DumpCaching",          cmd_set_dump_caching,   NULL,        OR_ALL, "Dump cahing in logs"),
	AP_INIT_FLAG    ("OPENIAM_DumpRequests",         ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_dump_requests),       OR_ALL, "Dump each request in log"),
	AP_INIT_FLAG    ("OPENIAM_DumpResponse",         ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_dump_response),       OR_ALL, "Dump each response in log"),
	AP_INIT_FLAG    ("OPENIAM_DumpCurl",             ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_dump_curl),           OR_ALL, "Dump curl"),
	AP_INIT_FLAG    ("OPENIAM_DebugCookies",         ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_debug_cookies),       OR_ALL, "Dump cookies and encrypt/decrypt information"),
	AP_INIT_FLAG    ("OPENIAM_DebugFilters",         ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_debug_filters),       OR_ALL, "Dump reverse filters debug info"),
	AP_INIT_FLAG    ("OPENIAM_DebugKerberos",        ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_debug_kerb),          OR_ALL, "Dump Kerberos and SPNEGO debug info"),
	AP_INIT_FLAG    ("OPENIAM_DebugCert",            ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, is_debug_cert),          OR_ALL, "Dump Certificate authenticaiton"),

	AP_INIT_ITERATE ("OPENIAM_ExcludeURI",           cmd_set_exclude_uri,  NULL,                                                                OR_ALL, "Paths where r-proxy is completelly disabled"),
	AP_INIT_ITERATE ("OPENIAM_ExcludePrefix",        cmd_set_exclude_prefix, NULL,                                                              OR_ALL, "Paths where r-proxy is completelly disabled"),

	AP_INIT_ITERATE ("OPENIAM_SimpleCacheURI",       cmd_set_simple_cache_uri,  NULL,                                                                OR_ALL, "Paths where r-proxy use only first part of uri as caching id. Use with Caution!!!"),

	AP_INIT_ITERATE ("OPENIAM_NoAuthURI",            cmd_set_noauth_uri,  NULL,                                                                 OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE ("OPENIAM_NoAuthPrefix",         cmd_set_noauth_prefix, NULL,                                                               OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE ("OPENIAM_NoAuthSuffix",         cmd_set_noauth_suffix, NULL,                                                               OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE2("OPENIAM_NoAuthURIwithBackend",    cmd_set_noauth_uri_with_backend, NULL,                                                  OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE2("OPENIAM_NoAuthPrefixwithBackend", cmd_set_noauth_prefix_with_backend, NULL,                                               OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE2("OPENIAM_NoAuthSuffixwithBackend", cmd_set_noauth_suffix_with_backend, NULL,                                               OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE2("OPENIAM_NoAuthOnPath",         cmd_set_noauth_prefix_with_backend, NULL,                                                  OR_ALL, "Paths that should be skipped and we should not perform any authentication or authorization checks on these paths"),
	AP_INIT_ITERATE2("OPENIAM_SkipFormPostifCookie", cmd_set_skip_form_post_if_cookie, NULL,                                                    OR_ALL, "Skip form post if (auth?) coookie already set"),

	AP_INIT_ITERATE ("OPENIAM_GenerateFormPostURI",  cmd_set_generate_form_post_page, NULL,                                                     OR_ALL, "Generate Form post html page instead of reverse-proxied form post"),
	AP_INIT_ITERATE ("OPENIAM_FormPostURI",          cmd_set_form_post_uri, NULL,                                                               OR_ALL, "Form post will be made only for this path"),
	AP_INIT_FLAG    ("OPENIAM_Kerberos",             ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_enabled),            OR_ALL, "Enable Kerberos v5 SPNEGO Authentication"),
	AP_INIT_TAKE1   ("OPENIAM_KrbServiceName",       ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_service_name),       OR_AUTHCFG | RSRC_CONF, "Full or partial service name to be used by Apache for authentication."),
	AP_INIT_TAKE1   ("OPENIAM_KrbAuthRealms",        set_krb_realms,     NULL,                                                                  OR_AUTHCFG | RSRC_CONF, "Realms to attempt authentication against (can be multiple)."),
	AP_INIT_TAKE1   ("OPENIAM_KrbAuthRealm",         set_krb_realms,     NULL,                                                                  OR_AUTHCFG | RSRC_CONF, "Alias for OPENIAM_KrbAuthRealms."),
	AP_INIT_FLAG    ("OPENIAM_KrbSaveCredentials",   ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_save_credentials),   OR_AUTHCFG | RSRC_CONF, "Save and store credentials/tickets retrieved during auth."),
	AP_INIT_FLAG    ("OPENIAM_KrbVerifyKDC",         ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_verify_kdc),         OR_AUTHCFG | RSRC_CONF, "Verify tickets against keytab to prevent KDC spoofing attacks."),
	AP_INIT_TAKE1   ("OPENIAM_Krb5Keytab",           ap_set_file_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_keytab),             OR_AUTHCFG | RSRC_CONF, "Location of Kerberos V5 keytab file."),
	AP_INIT_TAKE1   ("OPENIAM_KrbKeytab",            ap_set_file_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_keytab),             OR_AUTHCFG | RSRC_CONF, "Alias for OPENIAM_Krb5KeyTab"),
	AP_INIT_FLAG    ("OPENIAM_KrbPrincipalOnly",     ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_principal_only),     OR_AUTHCFG | RSRC_CONF, "Use only user name from kerberos ticket"),
	AP_INIT_TAKE1   ("OPENIAM_KrbPrincipalSuffix",   ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_principal_suffix),   OR_AUTHCFG | RSRC_CONF, "Add this suffix to kerberos principal"),
	AP_INIT_TAKE1   ("OPENIAM_KrbPrincipalPrefix",   ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, krb_principal_prefix),   OR_AUTHCFG | RSRC_CONF, "Add this prefix to kerberos principal"),
	AP_INIT_ITERATE2("OPENIAM_Redirects",            cmd_set_redirects,  NULL,                                                                  OR_ALL, "Paths that should be redirected to another url"),
	AP_INIT_ITERATE2("OPENIAM_Redirect",             cmd_set_redirects,  NULL,                                                                  OR_ALL, "Alias for OPENIAM_Redirects"),
	AP_INIT_ITERATE2("OPENIAM_RedirectBeforeAuth",   cmd_set_redirects_before_auth,  NULL,                                                      OR_ALL, "Paths that should be redirected to another url before any authentication or authorization"),
	AP_INIT_ITERATE2("OPENIAM_TargetServer",         cmd_set_target_server, NULL,                                                               OR_ALL, "redirect not to server from ESB response but to diferent server"),
	AP_INIT_ITERATE ("OPENIAM_Substitute",           cmd_set_substitute, NULL,                                                                  OR_ALL, "Pattern to filter the response content (s/foo/bar/[inf])"),
	AP_INIT_TAKE1   ("OPENIAM_IgnoreCharsInRedirect",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, ignore_invalid_chars_in_redirect), OR_ALL, "Ignore invalid chars in redirect"),
	AP_INIT_TAKE1   ("OPENIAM_MultipartString",      ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, multipart_str),          OR_ALL, "If set, multipart/form-post in form post requests used. if not - application/x-www-form-urlencoded"),
	AP_INIT_TAKE2   ("OPENIAM_MultipartStringForUri",cmd_set_multipart_string_for_uri, NULL,                                                    OR_ALL, "If set, multipart/form-post in form post for specified uri is used. if not - application/x-www-form-urlencoded"),
	AP_INIT_TAKE2   ("OPENIAM_ViewStateSource",      cmd_set_viewstate_url, NULL,                                                               OR_ALL, "Internal use."),
	AP_INIT_FLAG    ("OPENIAM_ViewStateSourceFollowLocation",   ap_set_flag_slot,   (void*)APR_OFFSETOF(iam_authn_dir_config_rec, viewstate_follow_location),   OR_AUTHCFG | RSRC_CONF, "Follow location then use curl to get data from OPENIAM_ViewStateSource"),
	AP_INIT_TAKE1   ("OPENIAM_ViewStateHolder",      ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, viewstate_str),          OR_ALL, "Replace fields with this value with real __VIEWSTATE hidden field"),
	AP_INIT_TAKE1   ("OPENIAM_ViewStateGeneratorHolder",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, viewstategenerator_str),    OR_ALL, "Replace fields with this value with real __VIEWSTATEGENERATOR hidden field"),
	AP_INIT_TAKE1   ("OPENIAM_EventValidationHolder",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, eventvalidation_str),    OR_ALL, "Replace fields with this value with real __EVENTVALIDATION hidden field"),
	AP_INIT_TAKE1   ("OPENIAM_EventTargetHolder",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, eventtarget_str),            OR_ALL, "Replace fields with this value with real __EVENTTARGET hidden field"),
	AP_INIT_TAKE1   ("OPENIAM_EventArgumentHolder",ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, eventargument_str),        OR_ALL, "Replace fields with this value with real __EVENTARGUMENT hidden field"),
	AP_INIT_TAKE1   ("OPENIAM_UnsetAllCookiesOnHit", cmd_set_unset_allcookies, NULL,  OR_ALL, "remove all cookies sending to backend for this url"),
	AP_INIT_TAKE2   ("OPENIAM_UnderConstruction",    cmd_set_under_construction, NULL,                                                          OR_ALL, "Under Construction r-proxyied page"),
	AP_INIT_TAKE1   ("OPENIAM_UnderConstructionRedirect",    ap_set_string_slot, (void*)APR_OFFSETOF(iam_authn_dir_config_rec, under_construction_redirect), OR_ALL, "Under Construction redirect"),

	AP_INIT_TAKE1   ("OPENIAM_ESBCacheTokensExpireTime",   cmd_set_tokens_expire,  NULL,                                                   OR_ALL, "ESB Cache tokens expiration time"),
	AP_INIT_TAKE1   ("OPENIAM_ESBCacheExpireTime",         cmd_set_esb_expire,  NULL,                                                      OR_ALL, "ESB Cache federation expiration time"),
	AP_INIT_TAKE1   ("OPENIAM_ESBCacheNoAuthExpireTime",   cmd_set_noauth_expire,  NULL,                                                   OR_ALL, "ESB Cache federation for noauth uris expiration time"),
#ifdef MEMCACHE_CACHE
	AP_INIT_TAKE1   ("OPENIAM_MemcaheCache",               cmd_set_memcache_esb_caching,  NULL,                                            OR_ALL, "Allow caching of ESB responses"),
	AP_INIT_TAKE1   ("OPENIAM_MemcaheServer",              cmd_set_memcache_host, NULL,                                                    OR_ALL, "Allow caching of ESB responses"),
	AP_INIT_TAKE1   ("OPENIAM_MemcahePort",                cmd_set_memcache_port, NULL,                                                    OR_ALL, "Allow caching of ESB responses"),
#endif
#ifdef SHARED_CACHE
	AP_INIT_TAKE1   ("OPENIAM_SharedCache",                cmd_set_shared_esb_caching,  NULL,                                            OR_ALL, "Allow caching of ESB responses"),
	AP_INIT_TAKE1   ("OPENIAM_SharedCacheSize",           cmd_set_shared_global_size,  NULL,                                            OR_ALL, "ESB Cache size"),
	AP_INIT_TAKE1   ("OPENIAM_SharedSyncTime",             cmd_set_shared_sync_time,  NULL,                                              OR_ALL, "ESB Cache sync time"),
	AP_INIT_TAKE1   ("OPENIAM_SharedCleanup",              cmd_set_shared_cleanup,  NULL,                                            OR_ALL, "ESB Cache expire time"),
#endif
	{ NULL }
};

module AP_MODULE_DECLARE_DATA iam_authn_module = {
	STANDARD20_MODULE_STUFF, 
	iam_authn_create_dir_config,
	NULL,
	iam_authn_create_server_config,
	iam_authn_merge_server_config,
	iam_config_cmds,
	iam_authn_hooks
};
