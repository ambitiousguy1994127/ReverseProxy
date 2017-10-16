/*
 * shared cache utils
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */

#ifndef __MOD_OPENIAM_CACHE_UTILS_H__
#define __MOD_OPENIAM_CACHE_UTILS_H__

//#ifdef SHARED_CACHE

#include <apr.h>
#include <apr_pools.h>
#include <apr_hash.h>
#include <apr_tables.h>
#include <apr_thread_mutex.h>

#include "shared_mem.h"

#define OPENIAM_BUF_ALIGN_SIZE         (64)
#define OPENIAM_BUF_ARRAY_INITIAL_SIZE (64*1024)

typedef struct buf_entry_t {
	apr_size_t          size;
	char*               buf;
	apr_time_t          expire;
} buf_entry_t;

typedef struct shared_cache_t {
	apr_pool_t         *pool;
	apr_thread_mutex_t *mutex;
	apr_hash_t         *hash;
	apr_array_header_t *free_entries;
	unsigned int        max_hash_size;
	apr_time_t          last_update;
	apr_time_t          update_delay;
	int                 is_logging;
	int                 need_cleanup;
} shared_cache_t;

shared_cache_t*    openiam_shm_cache_init(apr_pool_t* pool, unsigned int max_hash_size,
	unsigned int update_delay, int logging, int cleanup);

apr_status_t openiam_shm_cache_set     (shared_cache_t *sc, char *id, char* value, apr_time_t expire);
apr_status_t openiam_shm_cache_unset   (shared_cache_t *sc, char *id);
char*        openiam_shm_cache_get     (shared_cache_t *sc, char *id, apr_pool_t *pool);

apr_status_t openiam_shm_cache_set_token(shared_cache_t *sc, char *id, apr_time_t expire);
int          openiam_shm_cache_token_exists(shared_cache_t *sc, char *id, apr_pool_t *pool);

/* do not use this directly */
apr_status_t openiam_shm_cache_free(shared_cache_t *sc, buf_entry_t* entry);
void openiam_shm_cache_remove_expired(shared_cache_t *sc);
buf_entry_t* openiam_shm_cache_alloc(shared_cache_t *sc, apr_size_t size);

//#endif

#endif
