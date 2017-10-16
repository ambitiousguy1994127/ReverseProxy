/* jsmn_utils.h
 * jsmn helpers
 * Authors: OpenIAM Developers
 */

#ifndef __MOD_OPENIAM_JSMN_UTILS_H__
#define __MOD_OPENIAM_JSMN_UTILS_H__

#include <apr.h>
#include <jsmn.h>

char* openiam_jsmn_token_tostr(char *json, jsmntok_t *t);
char* openiam_jsmn_token_copystr(apr_pool_t *pool, char *json, jsmntok_t *t);
int openiam_jsmn_token_streq(char *json, jsmntok_t *t, const char* str);

#endif
