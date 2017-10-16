/*
 * Optimized versions of apr utils for OpenIAM Authenticaton
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */
#ifndef STR_UTILS_H
#define STR_UTILS_H

#include <stdio.h>
#include <ctype.h> /* for isalnum */
#ifdef __i386__
typedef __off64_t off64_t;
#endif
#include <apr.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_pools.h>

#define apr_isalnum(c)   (isalnum(((unsigned char)(c))))

/* the same as apr_pstrcat. copied from apr_strings.c, but with bigger MAX_SAVED_LENGTHS parameter for better speed. but with more stack memory used */
char *iam_pstrcat(apr_pool_t *a, ...);
char *iam_multipart_str_from_key_value_pairs(apr_pool_t *p, const apr_array_header_t *arr, const char* multipart_str);
char *iam_str_from_key_value_pairs(apr_pool_t *p, const apr_array_header_t *arr, const char sep, int skip_notpropagated, int escape);
char *iam_str_from_key_value_pairs_without_values(apr_pool_t *p, const apr_array_header_t *arr, const char sep, int skip_notpropagated);
void replace_placeholders(apr_pool_t *p, const apr_array_header_t *arr, const char* holder, const char* replacement);
char *iam_escape_uri(apr_pool_t *p, const char *path);
char *iam_unescape_uri(apr_pool_t *p, const char *src);
char *iam_encode_uri(apr_pool_t *p, const char *path);
char *iam_xml_encode_uri(apr_pool_t *p, const char *url);
char *openiam_fix_special_inplace(apr_pool_t *p, char *str);
int   is_valid_ip4(const char *ip);

#endif
