/* parse_cert_response.h
 * Parse certificate response header
 * Authors: OpenIAM Developers
 */

#ifndef __MOD_OPENIAM_PARSE_CERT_RESPONSE_H__
#define __MOD_OPENIAM_PARSE_CERT_RESPONSE_H__

#include <apr.h>
#include <apr_pools.h>
#include "str_utils.h"

apr_status_t openiam_parse_cert_response(apr_pool_t *pool, char *json, char **principal, char **error);

#endif /* __MOD_OPENIAM_PARSE_CERT_RESPONSE_H__ */
