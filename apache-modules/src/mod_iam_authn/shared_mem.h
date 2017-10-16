/* mod_openiam_shared_mem.h
 * Apache Module for OpenIAM Authenticaton an reverse-proxying
 * Author: Evgeniy Sergeev, <evgeniy.sereev@gmail.com> OpenIAM LLC
 */

#ifndef __MOD_OPENIAM_SHARED_MEM_H__
#define __MOD_OPENIAM_SHARED_MEM_H__

#ifdef SHARED_CACHE

#include <httpd.h>
#include <http_config.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include "shared_cache_utils.h"

#define OPENIAM_SHM_FILENAME          "openiam-shm"
#define OPENIAM_SHM_MUTEX             "openiam-shm-mutex"
#define OPENIAM_SHM_TOKENS_MUTEX      "openiam-shm-mutex-tokens"
#define OPENIAM_SHM_CONFIG_KEY        "openiam-shm-config-key"

#define OPENIAM_SHM_MAX_FEDERATION_BUF_SIZE (4096)
#define OPENIAM_SHM_MAX_TOKEN_BUF_SIZE      (256)

#define OPENIAM_SHM_FEDERATIONS_COUNT   (64*1024)
#define OPENIAM_SHM_TOKENS_COUNT        (64*1024)
#define OPENIAM_SHM_FEDERATIONS_SIZE    (OPENIAM_SHM_FEDERATIONS_COUNT*sizeof(openiam_shared_federation_rec))
#define OPENIAM_SHM_TOKENS_SIZE         (OPENIAM_SHM_TOKENS_COUNT*sizeof(openiam_shared_token_rec))
#define OPENIAM_SHM_SHM_REC_SIZE        (sizeof(openiam_shared_mem_rec))
#define OPENIAM_SHM_SIZE_TOTAL          (OPENIAM_SHM_SHM_REC_SIZE + OPENIAM_SHM_FEDERATIONS_SIZE + OPENIAM_SHM_TOKENS_SIZE)

typedef struct {
	apr_time_t expire;
	int        data_size;
	char       data[OPENIAM_SHM_MAX_FEDERATION_BUF_SIZE];
} openiam_shared_federation_rec;

typedef struct {
	apr_time_t expire;
	int        data_size;
	char       data[OPENIAM_SHM_MAX_TOKEN_BUF_SIZE];
} openiam_shared_token_rec;

typedef struct {
	apr_size_t federations_head;
	apr_size_t federations_tail;
	/* cache statistics */
	apr_size_t federations_hit;
	apr_size_t federations_miss;
	apr_time_t federations_expire_time;

	apr_size_t tokens_head;
	apr_size_t tokens_tail;
	/* cache statistics */
	apr_size_t tokens_hit;
	apr_size_t tokens_miss;
	apr_time_t tokens_expire_time;

	/* private key */
	char key[256];
} openiam_shared_mem_rec;

typedef struct {
	apr_shm_t          *shm;
	apr_size_t          size;
	char               *shm_filename;
	apr_global_mutex_t *shm_mutex_federations;
	apr_global_mutex_t *shm_mutex_tokens;
	char               *ptr;
} openiam_shared_mem_context;

void openiam_shm_set_global_federation(char *id, char *value, apr_size_t size, apr_time_t expire);
void openiam_shm_sync_with_global_federations(shared_cache_t *sc);

void openiam_shm_set_global_token(char *id, char *token, apr_size_t size, apr_time_t expire);
void openiam_shm_sync_with_global_tokens(shared_cache_t *sc);

void openiam_register_shm_hooks(apr_pool_t *p);

#endif

#endif
