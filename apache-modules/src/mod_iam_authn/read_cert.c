/*
 * Apache Module for OpenIAM Authenticaton an reverse-proxying
 * Authors: OpenIAM Developers
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
#include <mod_ssl.h>
#include "str_utils.h"
#include "iam_errors.h"

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https)   *ssl_is_https   = NULL;

apr_status_t openiam_read_cert(request_rec* r, char **out_pem)
{
	if ( ssl_is_https == NULL )
		ssl_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

	if ( ssl_is_https == NULL )
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to retrieve optional function: ssl_is_https. Is mod_ssl loaded?");
		return OPENIAM_NOT_SSL_CONN;
	}

	if ( !ssl_is_https(r->connection) )
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to read client certificate on non-ssl connection");
		return OPENIAM_NOT_SSL_CONN;
	}

	const char *client_cert = NULL;

	void *data = NULL;
	if ( apr_pool_userdata_get(&data, "OPENIAM_CLIENT_CERT", r->connection->pool) == APR_SUCCESS && data != NULL )
	{
		client_cert = data;
	}

	if ( client_cert == NULL )
	{
		ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
		if ( ssl_var_lookup == NULL )
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Unable to retrieve optional function ssl_var_lookup is missing. ");
			return OPENIAM_NOT_SSL_CONN;
		}

		client_cert = ssl_var_lookup(r->pool, r->server, r->connection, r, "SSL_CLIENT_CERT");
	}

	if ( client_cert == NULL )
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "Unable to read client certificate");
		return OPENIAM_NO_CLIENT_CERT;
	}

	const char *saved_client_cert = apr_pstrdup(r->connection->pool, client_cert);
	apr_pool_userdata_set((const void*)saved_client_cert, "OPENIAM_CLIENT_CERT", NULL, r->connection->pool);
	if ( out_pem )
		*out_pem = client_cert;

	return APR_SUCCESS;
}
