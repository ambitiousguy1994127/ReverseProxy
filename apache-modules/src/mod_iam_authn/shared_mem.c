/* shared_mem.c
 * Apache Module for OpenIAM Authenticaton an reverse-proxying
 * Author: Evgeniy Sergeev, <evgeniy.sereev@gmail.com> OpenIAM LLC
 */

#ifdef SHARED_CACHE

#include <httpd.h>
#include <http_core.h>
#include <http_log.h>
#include <apr_global_mutex.h>
#include "str_utils.h"
#include "shared_mem.h"
#include "version.h"
#include "iam_errors.h"
#ifdef AP_NEED_SET_MUTEX_PERMS
#include <unixd.h>
#endif

//#include <util_mutex.h>

openiam_shared_mem_context ctx;

openiam_shared_federation_rec* openiam_shm_federations()
{
	if ( ctx.ptr && ctx.size ) {
		return (openiam_shared_federation_rec*)(ctx.ptr + OPENIAM_SHM_SHM_REC_SIZE);
	}
	return NULL;
}

openiam_shared_token_rec* openiam_shm_tokens()
{
	if ( ctx.ptr && ctx.size ) {
		return (openiam_shared_token_rec*)(ctx.ptr + OPENIAM_SHM_SHM_REC_SIZE + OPENIAM_SHM_FEDERATIONS_SIZE);
	}
	return NULL;
}

openiam_shared_mem_rec* openiam_shm_rec()
{
	if ( ctx.ptr && ctx.size ) {
		return (openiam_shared_mem_rec*)(ctx.ptr);
	}
	return NULL;
}

static apr_status_t remove_locks(void *data)
{
	if (ctx.shm_mutex_federations) {
		apr_global_mutex_destroy(ctx.shm_mutex_federations);
		ctx.shm_mutex_federations = NULL;
	}
	if (ctx.shm_mutex_tokens) {
		apr_global_mutex_destroy(ctx.shm_mutex_tokens);
		ctx.shm_mutex_tokens = NULL;
	}
	return APR_SUCCESS;
}

static apr_status_t openiam_shm_cleanup(void *data)
{
	if ( ctx.shm ) {
		return apr_shm_destroy(ctx.shm);
	}
	return APR_SUCCESS;
}

static apr_status_t openiam_shm_init(apr_pool_t *p, apr_size_t shm_size)
{
	apr_status_t ret = apr_shm_create(&ctx.shm, shm_size, NULL, p);

	if ( ret != APR_SUCCESS ) {
		/* For a name-based segment, remove it first in case of a previous unclean shutdown. */
		apr_shm_remove(OPENIAM_SHM_FILENAME, p);
		ret = apr_shm_create(&ctx.shm, shm_size, OPENIAM_SHM_FILENAME, p);
	}
	
	if ( ret != APR_SUCCESS ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "Could not allocate shared memory");
		return ret;
	}

	ctx.ptr  = apr_shm_baseaddr_get(ctx.shm);
	ctx.size = apr_shm_size_get(ctx.shm);

	if ( ctx.size < shm_size ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "shared memory segment too small. need %ld bytes", shm_size);
		return APR_ENOSPC;
	}
	/* clear shared memory */
	memset(ctx.ptr, 0, ctx.size);

	ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "allocated %" APR_SIZE_T_FMT " bytes of shared cache for OpenIAM", ctx.size);

	return APR_SUCCESS;
}

static int openiam_shm_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptmp)
{
/*
	apr_status_t ret = ap_mutex_register(pconf, openiam_shm_mutex_id, NULL, APR_LOCK_DEFAULT, 0);
	if ( ret != APR_SUCCESS ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "failed to register %s mutex", openiam_shm_mutex_id);
		return OK;
	}
*/
	return OK;
}

static int openiam_shm_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptmp, server_rec *s)
{
	void *data = NULL;
	static const char *userdata_key = OPENIAM_SHM_CONFIG_KEY;
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);

	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	openiam_shm_init(pconf, OPENIAM_SHM_SIZE_TOTAL);

	apr_status_t ret = apr_global_mutex_create(&ctx.shm_mutex_federations, OPENIAM_SHM_MUTEX, APR_LOCK_DEFAULT, s->process->pool);
	if ( ret == APR_SUCCESS ) {
#ifdef AP_NEED_SET_MUTEX_PERMS
		int rc = unixd_set_global_mutex_perms(ctx.shm_mutex_federations);
		if ( rc != APR_SUCCESS ) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pconf, "Could not set permissions on global parent mutex %s", OPENIAM_SHM_MUTEX);
		}
#endif
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pconf, "failed to create %s mutex", OPENIAM_SHM_MUTEX);
	}

	ret = apr_global_mutex_create(&ctx.shm_mutex_tokens, OPENIAM_SHM_TOKENS_MUTEX, APR_LOCK_DEFAULT, s->process->pool);
	if ( ret == APR_SUCCESS ) {
#ifdef AP_NEED_SET_MUTEX_PERMS
		int rc = unixd_set_global_mutex_perms(ctx.shm_mutex_tokens);
		if ( rc != APR_SUCCESS ) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pconf, "Could not set permissions on global parent mutex %s", OPENIAM_SHM_TOKENS_MUTEX);
		}
#endif
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, pconf, "failed to create %s mutex", OPENIAM_SHM_TOKENS_MUTEX);
	}


	apr_pool_cleanup_register(pconf, NULL, remove_locks, apr_pool_cleanup_null);
	return OK;
}

static void openiam_shm_child_init(apr_pool_t *p, server_rec *s)
{
	apr_status_t ret = apr_global_mutex_child_init(&ctx.shm_mutex_federations, OPENIAM_SHM_MUTEX, p);
	if ( ret != APR_SUCCESS ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "failed to initialise mutex %s in child_init", OPENIAM_SHM_MUTEX);
	}

	ret = apr_global_mutex_child_init(&ctx.shm_mutex_tokens, OPENIAM_SHM_TOKENS_MUTEX, p);
	if ( ret != APR_SUCCESS ) {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "failed to initialise mutex %s in child_init", OPENIAM_SHM_TOKENS_MUTEX);
	}

	if ( ctx.shm == NULL ) {
		/* attach only if we don't inherite shared handle yet. */
		apr_status_t ret = apr_shm_attach(&ctx.shm, NULL, p);

		if ( ret != APR_SUCCESS ) {
			ret = apr_shm_attach(&ctx.shm, OPENIAM_SHM_FILENAME, p);
		}

		if ( ret != APR_SUCCESS ) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, p, "Could not attach to shared memory");
			return;
		}
	} else {
		ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p, "child process inherited shm. no need to attach.");
	}

	ctx.ptr  = apr_shm_baseaddr_get(ctx.shm);
	ctx.size = apr_shm_size_get(ctx.shm);

	openiam_shared_mem_rec* rec = openiam_shm_rec();

	ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, p, "attached child pid=%d to %" APR_SIZE_T_FMT " bytes of shared cache for OpenIAM.", getpid(), ctx.size);
}


void openiam_shm_set_global_federation(char *id, char *value, apr_size_t size, apr_time_t expire)
{
#ifdef LOG_SHARED_ERRORS
	ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, NULL, "set_global_federation(%s, %%" APR_SIZE_T_FMT, id, size);
#endif

	if ( size > OPENIAM_SHM_MAX_FEDERATION_BUF_SIZE ) {
		return;
	}

	apr_status_t ret = apr_global_mutex_lock(ctx.shm_mutex_federations);
	if (ret == APR_SUCCESS) {
		openiam_shared_mem_rec* rec = openiam_shm_rec();
		apr_size_t i = rec->federations_head;
#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "child set global entry[%" APR_SIZE_T_FMT "] %s", i, id);
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "before set: tail = %lu head = %lu", rec->federations_tail, rec->federations_head);
#endif
		openiam_shared_federation_rec* federations = openiam_shm_federations();

		federations[i].expire = expire;
		federations[i].data_size = size;
		memcpy(federations[i].data, value, size);

		rec->federations_head++;
		if ( rec->federations_head >= OPENIAM_SHM_FEDERATIONS_COUNT ) {
			rec->federations_head = 0;
			if ( rec->federations_tail == 0 ) {
				rec->federations_tail ++;
			}
		}
		if ( rec->federations_head == rec->federations_tail ) {
			rec->federations_tail ++;
		}

#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "after set: tail = %lu head = %lu", rec->federations_tail, rec->federations_head);
#endif

		ret = apr_global_mutex_unlock(ctx.shm_mutex_federations);
		if (ret != APR_SUCCESS) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't unlock mutex %s in child. ret=%d", OPENIAM_SHM_MUTEX, ret);
		}
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't lock mutex %s in child. ret=%d", OPENIAM_SHM_MUTEX, ret);
	}
}

void openiam_shm_sync_with_global_federations(shared_cache_t *sc)
{
	apr_status_t ret = apr_global_mutex_lock(ctx.shm_mutex_federations);
	if (ret == APR_SUCCESS) {
		openiam_shared_mem_rec* rec = openiam_shm_rec();
		apr_size_t j = rec->federations_tail;

#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "before sync: tail = %lu head = %lu", rec->federations_tail, rec->federations_head);
#endif
		/* first of all move tail to first not expired item */
		apr_time_t current_time = apr_time_now();

		openiam_shared_federation_rec* federations = openiam_shm_federations();
		while ( 1 ) {
			if ( j == rec->federations_head ) {
				break;
			}
			if ( federations[j].expire > current_time ) {
				rec->federations_tail = j;
				break;
			}
			j ++;
			if ( j >= OPENIAM_SHM_FEDERATIONS_COUNT ) {
				j = 0;
			}
		}
		rec->federations_tail = j;

#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "sync: tail = %lu head = %lu", rec->federations_tail, rec->federations_head);
#endif

		while ( 1 ) {
			if ( j == rec->federations_head ) {
				break;
			}
			if ( federations[j].data ) {
				char *value = federations[j].data;
				apr_size_t len = strlen(value);
				char *key = value + len + 1;
#ifdef LOG_SHARED_ERRORS
				ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "need to sync key=%s", key);
#endif
				if ( apr_hash_count(sc->hash) < sc->max_hash_size ) {
					apr_size_t size = len + 1;
					apr_size_t id_size = strlen(key) + 1;
					buf_entry_t *new_entry = NULL;
					buf_entry_t *entry = apr_hash_get(sc->hash, key, APR_HASH_KEY_STRING);
					if ( entry ) {
						if ( entry->size >= federations[j].data_size ) {
							new_entry = entry;
						} else {
							openiam_shm_cache_free(sc, entry);
						}
					}
					if ( new_entry == NULL ) {
						new_entry = openiam_shm_cache_alloc(sc, federations[j].data_size);
					}
					if ( new_entry ) {
						memcpy(new_entry->buf, federations[j].data, federations[j].data_size);
						char *new_key = new_entry->buf + len + 1;
						new_entry->expire = federations[j].expire;
						apr_hash_set(sc->hash, new_key, APR_HASH_KEY_STRING, new_entry);
					} else {
						apr_hash_set(sc->hash, key, APR_HASH_KEY_STRING, NULL);
					}
				}
			}
			j ++;
			if ( j >= OPENIAM_SHM_FEDERATIONS_COUNT ) {
				j = 0;
			}
		}

		ret = apr_global_mutex_unlock(ctx.shm_mutex_federations);
		if (ret != APR_SUCCESS) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't unlock mutex %s in child. ret=%d", OPENIAM_SHM_MUTEX, ret);
		}
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't lock mutex %s in child. ret=%d", OPENIAM_SHM_MUTEX, ret);
	}
}

void openiam_shm_set_global_token(char *id, char *token, apr_size_t size, apr_time_t expire)
{
	if ( size > OPENIAM_SHM_MAX_TOKEN_BUF_SIZE ) {
		return;
	}

	apr_status_t ret = apr_global_mutex_lock(ctx.shm_mutex_tokens);
	if (ret == APR_SUCCESS) {
		openiam_shared_mem_rec* rec = openiam_shm_rec();
#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "child store token entry %s", id);
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "before set token.: tail = %lu head = %lu", rec->tokens_tail, rec->tokens_head);
#endif

		openiam_shared_token_rec* tokens = openiam_shm_tokens();

		apr_size_t i = rec->tokens_head;

		tokens[i].expire = expire;
		tokens[i].data_size = size;
		memcpy(tokens[i].data, token, size);

		rec->tokens_head++;
		if ( rec->tokens_head >= OPENIAM_SHM_TOKENS_COUNT ) {
			rec->tokens_head = 0;
			if ( rec->tokens_tail == 0 ) {
				rec->tokens_tail ++;
			}
		}
		if ( rec->tokens_head == rec->tokens_tail ) {
			rec->tokens_tail ++;
		}

#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "after set token.: tail = %lu head = %lu", rec->tokens_tail, rec->tokens_head);
#endif

		ret = apr_global_mutex_unlock(ctx.shm_mutex_tokens);
		if (ret != APR_SUCCESS) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't unlock mutex %s in child. ret=%d", OPENIAM_SHM_TOKENS_MUTEX, ret);
		}
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't lock mutex %s in child. ret=%d", OPENIAM_SHM_TOKENS_MUTEX, ret);
	}
}

void openiam_shm_sync_with_global_tokens(shared_cache_t *sc)
{
	apr_status_t ret = apr_global_mutex_lock(ctx.shm_mutex_tokens);
	if (ret == APR_SUCCESS) {
		openiam_shared_mem_rec* rec = openiam_shm_rec();
#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "before sync tokens: tail = %lu head = %lu", rec->tokens_tail, rec->tokens_head);
#endif

		/* first of all move tail to first not expired item */
		apr_time_t current_time = apr_time_now();

		openiam_shared_token_rec* tokens = openiam_shm_tokens();
		apr_size_t j = rec->tokens_tail;
		while ( 1 ) {
			if ( j == rec->tokens_head ) {
				break;
			}
			if ( tokens[j].expire > current_time ) {
				break;
			}
			j ++;
			if ( j >= OPENIAM_SHM_TOKENS_COUNT ) {
				j = 0;
			}
		}
		rec->tokens_tail = j;

#ifdef LOG_SHARED_ERRORS
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "sync tokens: tail = %lu head = %lu", rec->tokens_tail, rec->tokens_head);
#endif

		while ( 1 ) {
			if ( j == rec->tokens_head ) {
				break;
			}
			if ( tokens[j].data ) {
				char *value = tokens[j].data;
				apr_size_t len = strlen(value);
				char *key = value + len + 1;
#ifdef LOG_SHARED_ERRORS
				ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "need to sync token=%s", key);
#endif
				if ( apr_hash_count(sc->hash) < sc->max_hash_size ) {
					apr_size_t size = len + 1;
					apr_size_t id_size = strlen(key) + 1;
					buf_entry_t *new_entry = NULL;
					buf_entry_t *entry = apr_hash_get(sc->hash, key, APR_HASH_KEY_STRING);
					if ( entry ) {
						if ( entry->size >= (size + id_size) ) {
							new_entry = entry;
						} else {
							openiam_shm_cache_free(sc, entry);
						}
					}
					if ( new_entry == NULL ) {
						new_entry = openiam_shm_cache_alloc(sc, size + id_size);
					}
					if ( new_entry ) {
						memcpy(new_entry->buf, tokens[j].data, tokens[j].data_size);
						char *new_key = new_entry->buf + len + 1;
						new_entry->expire = tokens[j].expire;
						apr_hash_set(sc->hash, new_key, APR_HASH_KEY_STRING, new_entry);
					} else {
						apr_hash_set(sc->hash, key, APR_HASH_KEY_STRING, NULL);
					}
				}
			}
			j ++;
			if ( j >= OPENIAM_SHM_TOKENS_COUNT ) {
				j = 0;
			}
		}

		ret = apr_global_mutex_unlock(ctx.shm_mutex_tokens);
		if (ret != APR_SUCCESS) {
			ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't unlock mutex %s in child. ret=%d", OPENIAM_SHM_TOKENS_MUTEX, ret);
		}
	} else {
		ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "can't lock mutex %s in child. ret=%d", OPENIAM_SHM_TOKENS_MUTEX, ret);
	}
}


void openiam_register_shm_hooks(apr_pool_t *p)
{
	ap_hook_pre_config (openiam_shm_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(openiam_shm_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init (openiam_shm_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

#endif
