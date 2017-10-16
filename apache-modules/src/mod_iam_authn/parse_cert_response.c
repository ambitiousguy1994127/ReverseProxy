/* parse_cert_response.c
 * Parse certificate response
 * Authors: OpenIAM Developers
 */

#include <httpd.h>
#include <http_log.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_base64.h>
#include <jsmn.h>
#include <stdlib.h>
#include "jsmn_utils.h"
#include "str_utils.h"
#include "parse_jsmn.h"
#include "parse_cert_response.h"
#include "iam_errors.h"

/*

{"status":"SUCCESS","errorCode":null,"errorText":null,"responseValue":null,"errorTokenList":null,"principal":{"operation":"NO_CHANGE","loginId":"0000000057add9030157b3db33b6016a",
"login":"user1","lowerCaseLogin":"user1","managedSysId":"0","userId":"0000000057add9030157b3db335d0163","password":"**********","pwdEquivalentToken":null,
"challengeResponseFailCount":0,"pwdChanged":1476191319000,"pwdExp":1483967319000,"firstTimeLogin":0,"resetPassword":0,"isLocked":0,"status":null,"provStatus":"CREATED",
"initialStatus":null,"gracePeriod":1484312919000,"createDate":1476174542000,"createdBy":null,"currentLoginHost":null,"authFailCount":0,"lastAuthAttempt":1476191319000,
"canonicalName":null,"lastLogin":1476191319000,"isDefault":0,"passwordChangeCount":0,"lastLoginIP":"127.0.0.1","prevLogin":1476191319000,"prevLoginIP":"127.0.0.1",
"pswdResetToken":null,"pswdResetTokenExp":null,"loginAttributes":[],"passwordHistory":[],"selected":false,"origPrincipalName":null,"managedSysName":null,
"lastUpdate":1476174592000},"failure":false,"success":true}

{"status":"FAILURE","errorCode":"INVALID_LOGIN","errorText":null,"responseValue":null,"error
TokenList":null,"principal":null,"failure":true,"success":false}


 */

#define JSMN_INITIAL_TOKENS_COUNT (64)

typedef struct {
	apr_pool_t *pool;
	int success;
	char* principal;
	char* error_code;
	char* error_text;
} cert_response_callback_context_t;

apr_status_t openiam_parse_json_cert_response_callback(apr_pool_t *pool, void *ptr,
	char *key, char *value, char *state, apr_size_t array_index)
{
	cert_response_callback_context_t *ctx = (cert_response_callback_context_t*)ptr;

	if ( state == NULL )
	{
		if ( strcmp(key, "status") == 0 )
		{
			if ( strcmp( value, "SUCCESS" ) == 0 )
			{
				ctx->success = 1;
			}
		}
		else if ( strcmp(key, "errorCode") == 0 )
		{
			if ( value )
				ctx->error_code = apr_pstrdup(ctx->pool, value);
		}
		else if ( strcmp(key, "errorText") == 0 )
		{
			if ( value )
				ctx->error_text = apr_pstrdup(ctx->pool, value);
		}
		else if ( strcmp(key, "failure") == 0 )
		{
			if ( strcmp( value, "false" ) != 0 )
			{
				ctx->success = 0;
			}
		}
		else if ( strcmp(key, "success") == 0 )
		{
			if ( strcmp( value, "true" ) == 0 )
			{
				ctx->success = 1;
			}
		}
	}
	else if ( strcmp(state, "principal") == 0 )
	{
		if ( strcmp(key, "login") == 0 )
		{
			if ( value )
			{
				ctx->principal = apr_pstrdup(ctx->pool, value);
			}
		}
	}

	return APR_SUCCESS;
}

apr_status_t openiam_parse_cert_response(apr_pool_t *pool, char *json, char **principal, char **error)
{
	jsmn_parser parser;
	jsmn_init(&parser);

	if ( json == NULL )
	{
		return APR_SUCCESS;
	}

	apr_size_t json_len = strlen(json);
	if ( json_len == 0 )
	{
		return APR_SUCCESS;
	}

	int tokens_count = JSMN_INITIAL_TOKENS_COUNT;

	jsmntok_t* tokens = apr_palloc(pool, sizeof(jsmntok_t)*tokens_count);
	if ( tokens == NULL  )
	{
		return OPENIAM_NOMEM_ERROR;
	}

	tokens_count = jsmn_parse(&parser, json, json_len, tokens, tokens_count);
	if ( tokens_count == JSMN_ERROR_NOMEM )
	{
		jsmn_init(&parser);
		tokens_count = jsmn_parse(&parser, json, json_len, NULL, 0);

		tokens = apr_palloc(pool, sizeof(jsmntok_t)*tokens_count);
		if ( tokens == NULL  )
		{
			return OPENIAM_NOMEM_ERROR;
		}

		jsmn_init(&parser);
		tokens_count = jsmn_parse(&parser, json, json_len, tokens, tokens_count);
	}

	if ( tokens_count < 0 )
	{
		return OPENIAM_JSON_ERROR;
	}

	cert_response_callback_context_t* ctx = apr_pcalloc(pool, sizeof(cert_response_callback_context_t));
	ctx->pool = pool;
	openiam_parse_json(pool, 0, json, tokens, 0, tokens_count, NULL, -1, openiam_parse_json_cert_response_callback, ctx);

	if ( principal && ctx->success && ctx->principal )
	{
		*principal = ctx->principal;
		return APR_SUCCESS;
	}

	if ( error && ctx->error_text )
	{
		*error = ctx->error_text;
	}

	return OPENIAM_JSON_ERROR;
}
