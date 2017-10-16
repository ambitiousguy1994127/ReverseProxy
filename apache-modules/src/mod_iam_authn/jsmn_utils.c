/* jsmn_utils.c
 * JSMN helpers
 * Authors: OpenIAM Developers
 */

#include <apr.h>
#include <apr_strings.h>
#include <jsmn.h>

char* openiam_jsmn_token_tostr(char *json, jsmntok_t *t)
{
	json[t->end] = '\0';
	return json + t->start;
}

char* openiam_jsmn_token_copystr(apr_pool_t *pool, char *json, jsmntok_t *t)
{
	if ( t->end == -1 || t->start == -1 )
		return NULL;
	apr_size_t l = t->end - t->start;
	char *s = apr_palloc(pool, l + 1);
	memcpy(s, json + t->start, l);
	s[l] = '\0';
	return s;
}

int openiam_jsmn_token_streq(char *json, jsmntok_t *t, const char* str)
{
	if (t->type == JSMN_STRING && (int) strlen(str) == t->end - t->start &&
		strncmp(json + t->start, str, t->end - t->start) == 0)
	{
		return 0;
	}
	return -1;
}
