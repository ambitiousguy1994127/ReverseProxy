/*
 * Debug Utils for Apache Module for OpenIAM Authenticaton
 * Author: Evgeniy Sergeev, OpenIAM LLC
 */

#include <http_log.h>
#include <apr_tables.h>
#include <apr_date.h>
#include <apr_base64.h>

#define iam_debug_dump_time_exp(r, prefix, t) \
do { ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, \
	"%s tm_isdst=%d, tm_year=%d, tm_mon=%d, tm_mday=%d, tm_yday=%d, tm_wday=%d, " \
	"tm_hour=%d, tm_min=%d, tm_sec=%d, tm_usec=%d, tm_gmtoff=%d", prefix, \
	t.tm_isdst, t.tm_year, t.tm_mon, t.tm_mday, t.tm_yday, t.tm_wday, \
	t.tm_hour, t.tm_min, t.tm_sec, t.tm_usec, t.tm_gmtoff); } while (0);

#define iam_debug_dump_time(r, prefix, tm) \
do {	apr_time_exp_t exp_time; \
	apr_time_exp_gmt(&exp_time, tm); \
	iam_debug_dump_time_exp(r, prefix, &exp_time); } while (0);

#define iam_debug_dump_array(r, arr, prefix, offset) \
do { \
	int i; \
	for (i = 0; i < arr->nelts; i++) { \
		const char *item   = ((char**)(arr->elts))[i]; \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%s%s%s", prefix, offset, item); \
	} \
} while (0);

#define iam_debug_dump_table(r, table, prefix, offset) \
do { \
	const apr_array_header_t *arr = apr_table_elts(table); \
	apr_table_entry_t *entries  = (apr_table_entry_t *)arr->elts; \
	int i; \
	for (i = 0; i < arr->nelts; i++) { \
		const char *key   = entries[i].key; \
		const char *value = entries[i].val; \
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%s%s%s=%s", prefix, offset, key, value); \
	} \
} while (0);

#define iam_debug_dump_request(r, prefix) \
do { \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->the_request :%s", prefix,	r->the_request); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->proxyreq    :%d", prefix,	r->proxyreq); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->header_only :%d", prefix,	r->header_only); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->protocol    :%s", prefix,	r->protocol); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->hostname    :%s", prefix,	r->hostname); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->content_type:%s", prefix,	r->content_type); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->clength:%ld",     prefix,	r->clength); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->handler     :%s", prefix,	r->handler); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->content_encoding :%s", prefix,	r->content_encoding); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->vlist_validator  :%s", prefix,	r->vlist_validator); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->user        :%s", prefix,	r->user); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->ap_auth_type:%s", prefix,	r->ap_auth_type); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->unparsed_uri:%s", prefix,	r->unparsed_uri); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->uri         :%s", prefix,	r->uri); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->filename    :%s", prefix,	r->filename); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->path_info   :%s", prefix,	r->path_info); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->args        :%s", prefix,	r->args); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->no_cache    :%d", prefix,	r->no_cache); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->no_local_copy:%d", prefix,	r->no_local_copy); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->headers_in  :",   prefix);	iam_debug_dump_table(r, r->headers_in, prefix,      "                "); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->headers_out :",   prefix);	iam_debug_dump_table(r, r->headers_out, prefix,     "                "); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->err_headers_out :", prefix);	iam_debug_dump_table(r, r->err_headers_out, prefix, "                "); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->subprocess_env :", prefix);	iam_debug_dump_table(r, r->subprocess_env, prefix,  "                "); \
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "%sr->notes       :", prefix);	iam_debug_dump_table(r, r->notes, prefix,  "                "); \
} while (0);
