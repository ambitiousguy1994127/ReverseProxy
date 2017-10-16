/*
 * memcache utils
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */

#ifndef __MOD_OPENIAM_MEMCACHE_UTILS_H__
#define __MOD_OPENIAM_MEMCACHE_UTILS_H__

#include <apr.h>
#include <apr_pools.h>
#ifdef MEMCACHE_CACHE

#include <apr_memcache.h>

apr_status_t openiam_memcache_init(apr_pool_t *pool, const char* host, int port, apr_memcache_server_t **memcache_server, apr_memcache_t **memcache_handle);

apr_status_t openiam_memcache_set(apr_memcache_t *mc, char *id, char* value, apr_uint32_t timeout, apr_pool_t *pool);
char*        openiam_memcache_get(apr_memcache_t *mc, char *id, apr_pool_t *pool);
#endif

#endif
