/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (c) 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the University of
 *    California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Optimized versions of apr utils for OpenIAM Authenticaton
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */

/* MAX_SAVED_LENGTHS modified */

#include "str_utils.h"
#include <arpa/inet.h>

#ifndef MAX_SAVED_LENGTHS
#define MAX_SAVED_LENGTHS (32)
#endif

/* the same as apr_pstrcat. copied from apr_strings.c, but with extended MAX_SAVED_LENGTHS */

char * iam_pstrcat(apr_pool_t *a, ...)
{
	char *cp, *argp, *res;
	apr_size_t saved_lengths[MAX_SAVED_LENGTHS];
	int nargs = 0;

	/* Pass one --- find length of required string */

	apr_size_t len = 0;
	va_list adummy;

	va_start(adummy, a);

	while ( (cp = va_arg(adummy, char *)) != NULL ) {
		apr_size_t cplen = strlen(cp);
		if ( nargs < MAX_SAVED_LENGTHS ) {
			saved_lengths[nargs++] = cplen;
		}
		len += cplen;
	}

	va_end(adummy);

	/* Allocate the required string */

	res = (char *) apr_palloc(a, len + 1);
	cp = res;

	/* Pass two --- copy the argument strings into the result space */

	va_start(adummy, a);

	nargs = 0;
	while ( (argp = va_arg(adummy, char *)) != NULL ) {
		if ( nargs < MAX_SAVED_LENGTHS ) {
			len = saved_lengths[nargs++];
		} else {
			len = strlen(argp);
		}
		memcpy(cp, argp, len);
		cp += len;
	}

	va_end(adummy);

	*cp = '\0';
	return res;
}

/* based on apr_array_pstrcat and apr_pstrcat */
char * iam_str_from_key_value_pairs(apr_pool_t *p, const apr_array_header_t *arr, const char sep, int skip, int escape)
{
	char *cp, *old_cp, *res, **strpp;
	apr_size_t old_len, len;
	apr_size_t saved_lengths[MAX_SAVED_LENGTHS];
	char* saved_escaped_strs[MAX_SAVED_LENGTHS];
	int i, j, f;

	if ( arr->nelts <= 0 || arr->elts == NULL ) {    /* Empty table? */
		return NULL;
	}

	/* Pass one --- find length of required string */

	old_len = len = 0;
	f = 0;
	for ( i = 0, j = 0, strpp = (char **) arr->elts; ; ++strpp ) {
		if ( i % 3 == 0 ) {
			old_len = len;
		}
		if ( (i % 3) != 2 ) {
			if ( strpp && *strpp != NULL ) {
				apr_size_t cplen; 
				char *escaped = NULL;
				if ( escape ) {
					escaped = iam_escape_uri(p, *strpp);
					cplen = strlen(escaped);
				} else {
					cplen = strlen(*strpp);
				}
				if ( j < MAX_SAVED_LENGTHS ) {
					saved_lengths[j] = cplen;
					if ( escape ) {
						saved_escaped_strs[j] = escaped;
					}
					j++;
				}
				len += cplen;
				f = !f;
			}
			if ( sep || f ) {
				++len;
			}
		} else {
			if ( skip && strpp && *strpp == NULL ) {
				len = old_len;
			}
		}

		if ( ++i >= arr->nelts ) {
			break;
		}
	}

	res = (char *) apr_palloc(p, len + 1);
	old_cp = cp = res;

	/* Pass two --- copy the argument strings into the result space */

	for (i = 0, j = 0, strpp = (char **) arr->elts; ; ++strpp ) {
		if ( i % 3 == 0 ) {
			old_len = len;
			old_cp = cp;
		}
		if ( (i % 3) != 2 ) {
			if ( strpp && *strpp != NULL ) {
				char *str = *strpp;
				if ( j < MAX_SAVED_LENGTHS ) {
					len = saved_lengths[j];
					if ( escape ) {
						str = saved_escaped_strs[j];
					}
					j++;
				} else {
					if ( escape ) {
						str = iam_escape_uri(p, str);
					}
					len = strlen(str);
				}
				memcpy(cp, str, len);
				cp += len;
				f = !f;
			}
			if ( f ) {
				*cp++ = '=';
			} else if ( sep && (i < (arr->nelts-3)) ) {
				*cp++ = sep;
			}
		} else {
			if ( skip && strpp && *strpp == NULL ) {
				len = old_len;
				cp  = old_cp;
			}
		}
		if ( ++i >= arr->nelts ) {
			break;
		}
	}

	*cp = '\0';
	return res;
}


/* based on apr_array_pstrcat and apr_pstrcat */
char * iam_str_from_key_value_pairs_without_values(apr_pool_t *p, const apr_array_header_t *arr, const char sep, int skip)
{
	char *cp, *old_cp, *res, **strpp;
	apr_size_t old_len, len;
	apr_size_t saved_lengths[MAX_SAVED_LENGTHS];
	int i, j;

	if ( arr->nelts <= 0 || arr->elts == NULL ) {    /* Empty table? */
		return NULL;
	}

	/* Pass one --- find length of required string */

	old_len = len = 0;
	for ( i = 0, j = 0, strpp = (char **) arr->elts; ; strpp ++ ) {
		if ( (i % 3) == 0 ) {
			old_len = len;
			old_cp = cp;
			if ( strpp && *strpp != NULL ) {
				apr_size_t cplen = strlen(*strpp);
				if ( j < MAX_SAVED_LENGTHS ) {
					saved_lengths[j++] = cplen;
				}
				len += cplen;
			}
			if ( sep ) {
				++len;
			}
		} else if ( skip && ((i % 3) == 2) ) {
			if ( strpp && *strpp == NULL ) {
				old_len = len;
				old_cp  = cp;
			}
		}
		if ( ++i >= arr->nelts ) {
			break;
		}
	}

	res = (char *) apr_palloc(p, len + 1);
	old_cp = cp = res;

	/* Pass two --- copy the argument strings into the result space */

	for ( i = 0, j = 0, strpp = (char **) arr->elts; ; strpp ++ ) {
		if ( (i % 3) == 0 ) {
			old_len = len;
			old_cp = cp;
			if ( strpp && *strpp != NULL ) {
				if ( j < MAX_SAVED_LENGTHS ) {
					len = saved_lengths[j++];
				} else {
					len = strlen(*strpp);
				}
				old_cp = cp;
				memcpy(cp, *strpp, len);
				cp += len;
			}
			if ( sep && (i < (arr->nelts-3)) ) {
				*cp++ = sep;
			}
		} else if ( skip && ((i % 3) == 2) ) {
			if ( strpp && *strpp == NULL ) {
				cp = old_cp;
				len = old_len;
			}
		}
		if ( ++i >= arr->nelts ) {
			break;
		}
	}

	*cp = '\0';
	return res;
}

#define MULTIPART_HEADER                "Content-Disposition: form-data; name="
#define MULTIPART_HEADER_LEN            (37)
#define MULTIPART_CONTENTTYPE           "Content-Type: text/plain"
#define MULTIPART_CONTENTTYPE_LEN       (24)
#define MULTIPART_TT    "--"
#define MULTIPART_RN    "\r\n"

/* based on apr_array_pstrcat and apr_pstrcat */
char * iam_multipart_str_from_key_value_pairs(apr_pool_t *p, const apr_array_header_t *arr, const char* boundary)
{
	/* Check arguments */
	if ( boundary == NULL ) {
		return NULL;
	}
	if ( arr->nelts <= 0 || arr->elts == NULL ) {    /* Empty table? */
		return NULL;
	}

	char *cp, *res, **strpp;
	int i;
	apr_size_t boundary_len = strlen(boundary);
	apr_size_t len = 0;

	/* Pass one --- find length of required string */
	for ( i = 0, strpp = (char **) arr->elts; i < arr->nelts; ++strpp, ++i ) {
		const int j =  i % 3;
		if ( j == 2 ) {
			continue;
		}
		if ( strpp && *strpp != NULL ) {
			apr_size_t cplen = strlen(*strpp);
			if ( j == 0 ) {
				len = len + 2 + boundary_len + 2 + MULTIPART_HEADER_LEN + 2 + cplen + 2 + 2;
			} else /* if ( j == 1 ) */ {
				len = len + cplen + 2;
			}
		}
	}
	len = len + 2 + boundary_len + 2 + 2;

	res = (char *) apr_palloc(p, len + 1);
	cp = res;
	*cp = '\0';

	/* Pass two --- copy the argument strings into the result space */
	for ( i = 0, strpp = (char **) arr->elts; i < arr->nelts; ++strpp, ++i ) {
		const int j = i % 3;
		if ( j == 2 ) {
			continue;
		}
		if ( strpp && *strpp != NULL ) {
			if ( j == 0 ) {
				strcat(cp, MULTIPART_TT); 
				strcat(cp, boundary); 
				strcat(cp, MULTIPART_RN); 
				strcat(cp, MULTIPART_HEADER "\"");
				strcat(cp, *strpp);
				strcat(cp, "\"" MULTIPART_RN MULTIPART_RN);
			} else /* if ( j == 1 ) */ {
				strcat(cp, *strpp);
				strcat(cp, MULTIPART_RN);
			}
		}
	}

	strcat(cp, MULTIPART_TT); 
	strcat(cp, boundary); 
	strcat(cp, MULTIPART_TT); 
	strcat(cp, "\r\n");

	return res;
}


/* escape functions is from mod_rewrite.c */

static const char c2x_table[] = "0123456789ABCDEF";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix,
                                     unsigned char *where)
{
#if APR_CHARSET_EBCDIC
	what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);
#endif /*APR_CHARSET_EBCDIC*/
	*where++ = prefix;
	*where++ = c2x_table[what >> 4];
	*where++ = c2x_table[what & 0xf];
	return where;
}

/*
 * Escapes a uri in a similar way as php's urlencode does.
 * Based on ap_os_escape_path in server/util.c
 */
char *iam_escape_uri(apr_pool_t *p, const char *path)
{
	char *copy = apr_palloc(p, 3 * strlen(path) + 3);
	const unsigned char *s = (const unsigned char *)path;
	unsigned char *d = (unsigned char *)copy;
	unsigned c;
	while ( (c = *s) ) {
		if ( apr_isalnum(c) || c == '_' ) {
			*d++ = c;
		} else if ( c == ' ' ) {
			*d++ = '+';
		} else {
			d = c2x(c, '%', d);
		}
		++s;
	}
	*d = '\0';
	return copy;
}

char *iam_encode_uri(apr_pool_t *p, const char *path)
{
	char *copy = apr_palloc(p, 3 * strlen(path) + 3);
	const unsigned char *s = (const unsigned char *)path;
	unsigned char *d = (unsigned char *)copy;
	unsigned c;
	while ( (c = *s) ) {
		/* TODO: check that list of chars that should not be encoded. */
		if ( apr_isalnum(c) || c == '_'  || c == '/' || c == '.' /* || c == '?' || c == '&' || c == '+' || c == '-' */) {
			*d++ = c;
		} else {
			d = c2x(c, '%', d);
		}
		++s;
	}
	*d = '\0';
	return copy;
}

char *iam_xml_encode_uri(apr_pool_t *p, const char *url)
{
// & in &amp;
// < in &lt;
// " in &quot;
// ' in &apos;
// > in &gt;

	const unsigned char *s = (const unsigned char *)url;
	unsigned c;
	int len = 0;
	while ( (c = *s) )
	{
		if ( c == '&' )
		{
			len += 5;
		}
		else if ( c == '"' || c == '\'' )
		{
			len += 6;
		}
		else if ( c == '<' || c == '>' )
		{
			len += 4;
		}
		else
		{
			len ++;
		}
		++s;
	}

	char *copy = apr_palloc(p, len + 1);
	s = (const unsigned char *)url;
	unsigned char *d = (unsigned char *)copy;
	while ( (c = *s) )
	{
		if ( c == '&' )
		{
			memcpy(d, "&amp;", 5);
			d += 5;
		}
		else if ( c == '"' )
		{
			memcpy(d, "&quot;", 6);
			len += 6;
		}
		else if ( c == '\'' )
		{
			memcpy(d, "&apos;", 6);
			len += 6;
		}
		else if ( c == '<' )
		{
			memcpy(d, "&lt;", 4);
			len += 4;
		}
		else if ( c == '>' )
		{
			memcpy(d, "&gt;", 4);
			len += 4;
		}
		else
		{
			*d++ = c;
		}
		++s;
	}
	*d = '\0';
	return copy;
}

char *iam_unescape_uri(apr_pool_t *p, const char *src)
{
	apr_size_t len = strlen(src);
	char *result = apr_palloc(p, len + 1);
	char *dst = result;
	char a, b;
	while (*src) {
		if ( (*src == '%') &&
			((a = src[1]) && (b = src[2])) &&
			(isxdigit(a) && isxdigit(b)) ) {
				if (a >= 'a')
					a -= 'a'-'A';
				if (a >= 'A')
					a -= ('A' - 10);
				else
					a -= '0';
				if (b >= 'a')
					b -= 'a'-'A';
				if (b >= 'A')
					b -= ('A' - 10);
				else
					b -= '0';
			*dst++ = 16*a+b;
			src+=3;
		} else {
			*dst++ = *src++;
		}
	}
	*dst++ = '\0';
	return result;
}

int is_valid_ip4(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr));
}


/* based on apr_array_pstrcat and apr_pstrcat */
void replace_placeholders(apr_pool_t *p, const apr_array_header_t *arr, const char* holder, const char* replacement)
{
	char **strpp;
	int i;

	if ( arr->nelts <= 0 || arr->elts == NULL ) {    /* Empty table? */
		return;
	}

	for ( i = 0, strpp = (char **) arr->elts; i < arr->nelts; ++strpp, ++i ) {
		if ( (i % 3) == 1 ) {
			if ( strpp && *strpp != NULL ) {
				if ( strcmp(*strpp, holder) == 0 ) {
					*strpp = (char*)replacement;
				}
			}
		}
	}
}

char *openiam_fix_special_inplace(apr_pool_t *p, char *str)
{
	apr_size_t len = strlen(str);
	while ( 1 ) {
		char *s = strstr(str, "\\n");
		if ( s ) {
			*s = '\n';
			memcpy(s+1, s+2, len - (s - str) - 1);
			str[len-1] = '\0';
			len = len - 1;
		} else {
			break;
		}
	}
	return str;
}
