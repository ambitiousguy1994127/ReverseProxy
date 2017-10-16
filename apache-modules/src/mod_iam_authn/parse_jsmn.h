/* parse_jsmn.h
 * JSON common jsmn parser
 * Authors: OpenIAM Developers
 */

#ifndef __MOD_OPENIAM_PARSE_JSMN_H__
#define __MOD_OPENIAM_PARSE_JSMN_H__

#include <apr.h>
#include <apr_pools.h>
#include "str_utils.h"

typedef apr_status_t (*openiam_parse_json_callback_func)(apr_pool_t *pool, void *ptr,
	char *key, char *value, char *state, apr_size_t array_index);
apr_size_t openiam_parse_json(apr_pool_t *pool, apr_size_t level, char *json, jsmntok_t* tokens,
		apr_size_t start, apr_size_t length, char *state, apr_size_t array_index,
		openiam_parse_json_callback_func func, void *ptr);

#endif
