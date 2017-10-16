#include <apr.h>
#include <apr_pools.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <httpd.h>
#include <http_log.h>

#ifdef SHARED_CACHE

#include "iam_errors.h"
#include "shared_mem.h"
#include "shared_cache_utils.h"

static apr_status_t openiam_shm_cache_trylock(shared_cache_t *sc);
static apr_status_t openiam_shm_cache_lock(shared_cache_t *sc);
static apr_status_t openiam_shm_cache_unlock(shared_cache_t *sc);


static void openiam_shm_cache_log_error(char *comment)
{
	ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "SHM error %s", comment);
}

void openiam_shm_cache_dump_stat(shared_cache_t *sc)
{
	if ( sc->is_logging ) {
		ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, NULL, "SHM stat: hash count: %d free entries %d/%d",
			apr_hash_count(sc->hash), sc->free_entries->nelts, sc->free_entries->nalloc);
	}
}

static void openiam_shm_cache_dump_hash(shared_cache_t *sc, char *comment)
{
	if ( !sc->is_logging ) {
		return;
	}

	char now_buf[APR_RFC822_DATE_LEN*2];
    	memset(now_buf, 0, sizeof(now_buf));
	apr_status_t ret = apr_rfc822_date(now_buf, apr_time_now());
	if ( ret != APR_SUCCESS ) {
		strcpy(now_buf, "(error parsing time)");
	}

	ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "SHM dump %s (now:%s)", comment, now_buf);
	apr_hash_index_t *hi = apr_hash_first(sc->pool, sc->hash);
	int i = 0;
	for (; hi; hi = apr_hash_next(hi)) {
		const char  *k;
		buf_entry_t *v;
		apr_ssize_t klen;
		i++;
		apr_hash_this(hi, (const void**)&k, &klen, (void**)&v);

		if ( k && v && klen ) {
			char buf[APR_RFC822_DATE_LEN*2];
    			memset(buf, 0, sizeof(buf));
			apr_status_t ret = apr_rfc822_date(buf, v->expire);
			if ( ret != APR_SUCCESS ) {
				strcpy(buf, "(error parsing time)");
			}
			ap_log_perror(APLOG_MARK, APLOG_NOTICE, 0, NULL, "SHM: #%d, key=%s, expire=%s value size=%" APR_SIZE_T_FMT, i, k, buf, v->size);
		}
	}
	openiam_shm_cache_dump_stat(sc);
}

static apr_status_t openiam_shm_cache_done(void *data)
{
	shared_cache_t *sc = (shared_cache_t*)data;

	openiam_shm_cache_dump_stat(sc);

	apr_thread_mutex_destroy(sc->mutex);
	sc->mutex = NULL;
	apr_pool_destroy(sc->pool);

	return APR_SUCCESS;
}

shared_cache_t* openiam_shm_cache_init(apr_pool_t* pool, unsigned int max_hash_size,
	unsigned int update_delay, int logging, int cleanup)
{
	apr_pool_t *new_pool = NULL;
	apr_status_t ret = apr_pool_create(&new_pool, pool);
	if ( ret != APR_SUCCESS || new_pool == NULL ) {
		openiam_shm_cache_log_error("can't create memory pool");
		return NULL;
	}
	shared_cache_t *sc = apr_pcalloc(new_pool, sizeof(shared_cache_t));
	sc->pool    = new_pool;
	sc->is_logging = logging;
	sc->need_cleanup = cleanup;

	ret  = apr_thread_mutex_create(&sc->mutex, APR_THREAD_MUTEX_DEFAULT, sc->pool);
	if ( ret != APR_SUCCESS || sc->mutex == NULL ) {
		openiam_shm_cache_log_error("can't create thread mutex");
		return NULL;
	}
	sc->hash          = apr_hash_make (sc->pool);
	sc->free_entries  = apr_array_make(sc->pool, OPENIAM_BUF_ARRAY_INITIAL_SIZE, sizeof(buf_entry_t));

	sc->max_hash_size = max_hash_size;
	sc->last_update   = apr_time_now();
	sc->update_delay  = apr_time_from_sec(update_delay);

	apr_pool_cleanup_register(pool, sc, openiam_shm_cache_done, apr_pool_cleanup_null);

	return sc;
}

static apr_status_t openiam_shm_cache_trylock(shared_cache_t *sc)
{
	if ( sc && sc->mutex ) {
		return apr_thread_mutex_trylock(sc->mutex);
	}
	return APR_EINVAL;
}

static apr_status_t openiam_shm_cache_lock(shared_cache_t *sc)
{
	if ( sc && sc->mutex ) {
		return apr_thread_mutex_lock(sc->mutex);
	}
	return APR_EINVAL;
}

static apr_status_t openiam_shm_cache_unlock(shared_cache_t *sc)
{
	if ( sc && sc->mutex ) {
		return apr_thread_mutex_unlock(sc->mutex);
	}
	return APR_EINVAL;
}

apr_status_t openiam_shm_cache_unset(shared_cache_t *sc, char *id)
{
	return openiam_shm_cache_set(sc, id, NULL, 0);
}

buf_entry_t* openiam_shm_cache_alloc(shared_cache_t *sc, apr_size_t size)
{
	size = size + OPENIAM_BUF_ALIGN_SIZE;
	size = size - size % OPENIAM_BUF_ALIGN_SIZE;

	char*      buf      = NULL;
	apr_size_t buf_size = 0;

	buf_entry_t* item = (buf_entry_t*)sc->free_entries->elts;                                                    
	int i;
	// first of all try to find in free entries list
	for(i = 0; i < sc->free_entries->nelts; ++i, item++) {
		if ( item->buf && item->size == size ) {
			buf        = item->buf;
			buf_size   = item->size;
			item->buf  = NULL;
			item->size = 0;
			break;
		}
	}
	if ( buf == NULL ) {
		// second: try to find buffer bigger than needed 
		item = (buf_entry_t*)sc->free_entries->elts;                                                    
		for(i = 0; i < sc->free_entries->nelts; ++i, item++) {
			if ( item->buf && item->size >= size ) {
				buf        = item->buf;
				buf_size   = item->size;
				item->buf  = NULL;
				item->size = 0;
				break;
			}
		}
	}

	if ( buf == NULL ) {
		buf = apr_palloc(sc->pool, size);
		buf_size = size;
	}
	buf_entry_t* new_entry = apr_palloc(sc->pool, sizeof(buf_entry_t));
	new_entry->buf  = buf;
	new_entry->size = buf_size;
	return new_entry;
}

apr_status_t openiam_shm_cache_free(shared_cache_t *sc, buf_entry_t* entry)
{
	buf_entry_t* item = (buf_entry_t*)sc->free_entries->elts;                                                    
	int i;
	// first of all try to find in free entries list
	for(i = 0; i < sc->free_entries->nelts; ++i, item++) {
		if ( item->buf == NULL ) {
			item->buf  = entry->buf;
			item->size = entry->size;
			entry = NULL;
			break;
		}
	}
	if ( entry ) {
		item = (buf_entry_t*)apr_array_push(sc->free_entries);                                                    
		item->buf  = entry->buf;
		item->size = entry->size;
		entry = NULL;
	}

	return APR_SUCCESS;
}

void openiam_shm_cache_remove_expired(shared_cache_t *sc)
{
	if ( sc->need_cleanup == 0 ) {
		return;
	}

	apr_time_t current_time = apr_time_now();
	apr_hash_index_t *hi = apr_hash_first(sc->pool, sc->hash);
	int i = 0;
	for (; hi; ) {
		const char  *k;
		buf_entry_t *v;
		apr_ssize_t klen;
		i++;
		apr_hash_this(hi, (const void**)&k, &klen, (void**)&v);
		hi = apr_hash_next(hi);

		if ( v && v->buf ) {
			if ( v->expire < current_time ) {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "cleaning up: entry for %s expired", k);
				}
				openiam_shm_cache_free(sc, v);
				apr_hash_set(sc->hash, k, APR_HASH_KEY_STRING, NULL);
			}
		}
	}
}

static apr_status_t openiam_shm_cache_update_federations(shared_cache_t *sc)
{
//	if ( (sc->last_update + sc->update_delay)  > apr_time_now() ) {
		openiam_shm_cache_dump_hash(sc, "before update");
		// cleanup first, to have more space for sync.
		openiam_shm_cache_remove_expired(sc);
		openiam_shm_sync_with_global_federations(sc);
		sc->last_update = apr_time_now();
		openiam_shm_cache_dump_hash(sc, "after update");
		return APR_SUCCESS;
//	}
}

static apr_status_t openiam_shm_cache_update_tokens(shared_cache_t *sc)
{
//	if ( (sc->last_update + sc->update_delay)  > apr_time_now() ) {
		openiam_shm_cache_dump_hash(sc, "before tokens update");
		// cleanup first, to have more space for sync.
		openiam_shm_cache_remove_expired(sc);
		openiam_shm_sync_with_global_tokens(sc);
		sc->last_update = apr_time_now();
		openiam_shm_cache_dump_hash(sc, "after tokens update");
		return APR_SUCCESS;
//	}
}

apr_status_t openiam_shm_cache_set(shared_cache_t *sc, char *id, char* value, apr_time_t expire)
{
	if ( openiam_shm_cache_lock(sc) == APR_SUCCESS ) {
		openiam_shm_cache_dump_hash(sc, "before set");
		if ( value == NULL ) {
			if ( sc->is_logging ) {
				ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "clear %s", id);
			}
			buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
			if ( entry ) {
				openiam_shm_cache_free(sc, entry);
			}
			apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
		} else {
			if ( apr_hash_count(sc->hash) >= sc->max_hash_size ) {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "removing expired items then setting %s", id);
				}
				openiam_shm_cache_remove_expired(sc);
			}

			apr_size_t size = strlen(value) + 1;
			apr_size_t id_size = strlen(id) + 1;
			buf_entry_t *new_entry = NULL;
			buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
			if ( entry ) {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "already exists %s", id);
				}
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
				memcpy(new_entry->buf, value, size);
				char *new_id = new_entry->buf + size;
				memcpy(new_id, id, id_size);
				new_entry->expire = expire;
				apr_hash_set(sc->hash, new_id, APR_HASH_KEY_STRING, new_entry);
				openiam_shm_set_global_federation(new_id, new_entry->buf, new_entry->size, new_entry->expire);
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "set %s", id);
				}
			} else {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "unset %s", id);
				}
				apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
			}
		}
		openiam_shm_cache_dump_hash(sc, "after set");
		openiam_shm_cache_unlock(sc);
	}
	return APR_SUCCESS;
}

apr_status_t openiam_shm_cache_set_token(shared_cache_t *sc, char *id, apr_time_t expire)
{
	char* value = "";
	if ( openiam_shm_cache_lock(sc) == APR_SUCCESS ) {
		openiam_shm_cache_dump_hash(sc, "before set token");
		if ( value == NULL ) {
			buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
			if ( entry ) {
				openiam_shm_cache_free(sc, entry);
			}
			apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
		} else {
			if ( apr_hash_count(sc->hash) >= sc->max_hash_size ) {
				openiam_shm_cache_remove_expired(sc);
			}

			apr_size_t size = 1;
			apr_size_t id_size = strlen(id) + 1;
			buf_entry_t *new_entry = NULL;
			buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
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
				memcpy(new_entry->buf, "", 1);
				char *new_id = new_entry->buf + 1;
				memcpy(new_id, id, id_size);
				new_entry->expire = expire;
				apr_hash_set(sc->hash, new_id, APR_HASH_KEY_STRING, new_entry);
				openiam_shm_set_global_token(new_id, new_entry->buf, new_entry->size, expire);
			} else {
				apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
			}
		}
		openiam_shm_cache_dump_hash(sc, "after set token");
		openiam_shm_cache_unlock(sc);
	}
	return APR_SUCCESS;
}

char* openiam_shm_cache_get(shared_cache_t *sc, char *id, apr_pool_t *pool)
{
	char *result = NULL;

	if ( openiam_shm_cache_lock(sc) == APR_SUCCESS ) {
		openiam_shm_cache_dump_hash(sc, "before get");
		buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
		if ( entry && entry->buf ) {
			if ( entry->expire < apr_time_now() ) {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s expired", id);
				}
				openiam_shm_cache_free(sc, entry);
				apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
			} else {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s found", id);
				}
				result = apr_pstrdup(pool, entry->buf);
			}
		}
		if ( result == NULL ) {
			if ( sc->is_logging ) {
				ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s not found. trying to sync with shared data", id);
			}
			// result not found. try to sync with global shared data and try again.
			if ( openiam_shm_cache_update_federations(sc) == APR_SUCCESS ) {
				// synced return success. try to find entry agagin.
				entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
				if ( entry && entry->buf ) {
					if ( entry->expire < apr_time_now() ) {
						if ( sc->is_logging ) {
							ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s found after sync, but expired", id);
						}
						openiam_shm_cache_free(sc, entry);
						apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
					} else {
						if ( sc->is_logging ) {
							ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s found after sync", id);
						}
						result = apr_pstrdup(pool, entry->buf);
					}
				} else {
					if ( sc->is_logging ) {
						ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s not found after sync", id);
					}
				}
			}
		}
		openiam_shm_cache_unlock(sc);
	}
	return result;
}

int openiam_shm_cache_token_exists(shared_cache_t *sc, char *id, apr_pool_t *pool)
{
	int result = 0;

	if ( openiam_shm_cache_lock(sc) == APR_SUCCESS ) {
		openiam_shm_cache_dump_hash(sc, "before get token");
		buf_entry_t *entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
		if ( entry && entry->buf ) {
			if ( entry->expire < apr_time_now() ) {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "token entry for %s expired", id);
				}
				openiam_shm_cache_free(sc, entry);
				apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
			} else {
				if ( sc->is_logging ) {
					ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "token entry for %s found", id);
				}
				result = 1;
			}
		}
		if ( result == 0 ) {
			if ( sc->is_logging ) {
				ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "token entry for %s not found. trying to sync with shared data", id);
			}
			// result not found. try to sync with global shared data and try again.
			if ( openiam_shm_cache_update_tokens(sc) == APR_SUCCESS ) {
				// synced return success. try to find entry agagin.
				entry = apr_hash_get(sc->hash, id, APR_HASH_KEY_STRING); 
				if ( entry && entry->buf ) {
					if ( entry->expire < apr_time_now() ) {
						if ( sc->is_logging ) {
							ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "token entry for %s found after sync, but expired", id);
						}
						openiam_shm_cache_free(sc, entry);
						apr_hash_set(sc->hash, id, APR_HASH_KEY_STRING, NULL);
					} else {
						if ( sc->is_logging ) {
							ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "token entry for %s found after sync", id);
						}
						result = 1;
					}
				} else {
					if ( sc->is_logging ) {
						ap_log_perror(APLOG_MARK, APLOG_ERR, 0, NULL, "entry for %s not found after sync", id);
					}
				}
			}
		}
		openiam_shm_cache_unlock(sc);
	}
	return result;
}


#endif

