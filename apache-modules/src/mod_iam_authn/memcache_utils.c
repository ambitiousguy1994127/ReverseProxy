#include <apr.h>
#include <apr_pools.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#ifdef MEMCACHE_CACHE
#include <apr_memcache.h>
#endif
#include <httpd.h>
#include <http_log.h>
#include "memcache_utils.h"

#ifdef MEMCACHE_CACHE

apr_status_t openiam_memcache_init(apr_pool_t *pool, const char* host, int port,
	apr_memcache_server_t **memcache_server, apr_memcache_t **mc)
{
	apr_status_t ret = apr_memcache_create(pool, 1, 0x0, mc);
	if ( ret != APR_SUCCESS ) {
		return ret;
	}
	ret = apr_memcache_server_create(pool, host, port, 10, 100, 1000, 3600000, memcache_server);
	if ( ret != APR_SUCCESS ) {
		return ret;
	}
	ret = apr_memcache_add_server(*mc, *memcache_server);
	if ( ret != APR_SUCCESS ) {
		return ret;
	}
	ret = apr_memcache_enable_server(*mc, *memcache_server);
	if ( ret != APR_SUCCESS ) {
		return ret;
	}
	return APR_SUCCESS;
}

apr_status_t openiam_memcache_set(apr_memcache_t *mc, char *id, char* value, apr_uint32_t timeout, apr_pool_t *pool)
{
	return apr_memcache_set(mc, id, value, strlen(value)+1, timeout, 0x0);
}

char* openiam_memcache_get(apr_memcache_t *mc, char *id, apr_pool_t *pool)
{
	char *baton = NULL;
	apr_size_t len;
	apr_uint16_t flags;
	apr_status_t ret = apr_memcache_getp(mc, pool, id, &baton, &len, &flags);
	if ( ret == APR_SUCCESS ) {
		return baton;
	}
	return NULL;
}

#endif
