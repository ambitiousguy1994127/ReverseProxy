/* parse_jsmn.c
 * JSON common jsmn parser
 * Authors: OpenIAM Developers
 */

#include <apr.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <jsmn.h>
#include "jsmn_utils.h"
#include "str_utils.h"
#include "iam_errors.h"
#include "parse_jsmn.h"

apr_status_t openiam_parse_json_default_callback(apr_pool_t *pool, void *ptr,
	char *key, char *value, char *state, apr_size_t array_index)
{
	return APR_SUCCESS;
}

apr_size_t openiam_parse_json(apr_pool_t *pool, apr_size_t level, char *json, jsmntok_t* tokens,
		apr_size_t start, apr_size_t length, char *state, apr_size_t array_index,
		openiam_parse_json_callback_func func, void *ptr)
{
	if ( func == NULL )
		func = openiam_parse_json_default_callback;

	apr_size_t i = start;
	while( i < (start + length) )
	{
		char *key  = openiam_jsmn_token_tostr(json, tokens + i);

		if ( tokens[i].type == JSMN_STRING )
		{
			i++;

			if ( tokens[i].type == JSMN_ARRAY )
			{
				apr_size_t array_size = tokens[i].size;
				apr_size_t j;
				for ( j = 0; j < array_size; j++ )
				{
					char* safe_state = (state) ? state : "";
					char *sub_state = state ? apr_pstrcat(pool, safe_state, ".", key, NULL) : key;
					i = openiam_parse_json(pool, level + 1, json, tokens, i, 1, sub_state, j, func, ptr);
				}
			}
			else if ( tokens[i].type == JSMN_OBJECT )
			{
				apr_size_t sz = tokens[i].size;
				i++;
				i = openiam_parse_json(pool, level + 1, json, tokens, i, sz, key, -1, func, ptr);
			}
			else
			{
				char *value = openiam_jsmn_token_tostr(json, tokens + i);
				if ( tokens[i].type == JSMN_PRIMITIVE && strcmp(value, "null") == 0 )
					value = NULL;
				apr_status_t ret = func(pool, ptr, key, value, state, array_index);
				if ( ret != APR_SUCCESS )
					return ret;
				if ( start != 0 )
					length++;
				i++;
			}
		}
		else if ( tokens[i].type == JSMN_OBJECT || tokens[i].type == JSMN_ARRAY )
		{
			apr_size_t sz = tokens[i].size;
			i++;
			i = openiam_parse_json(pool, level + 1, json, tokens, i, sz, state, array_index, func, ptr);
		}
	}

	return i;
}
