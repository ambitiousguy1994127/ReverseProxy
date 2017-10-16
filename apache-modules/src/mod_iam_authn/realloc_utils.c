/* realloc_utils.c
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */

#include <apr.h>
#include "realloc_utils.h"

//TODO: find memory pool allocation alignment in apr sources. 8 bytes works for linux 64 bit 
#define ALIGN_SIZE (8)

void* openiam_realloc(apr_pool_t *pool, void *buf, apr_size_t buf_size, apr_size_t new_size)
{
	/* try to alloc small aligned to size of int memory block */
	void *first_bytes = NULL;
	if ( new_size - buf_size > ALIGN_SIZE ) {
		first_bytes = apr_palloc(pool, ALIGN_SIZE);
	}
	if ( first_bytes == NULL || first_bytes == buf + buf_size ) {
		void *rest_bytes = apr_palloc(pool, new_size - buf_size - (first_bytes ? ALIGN_SIZE : 0) );
		if ( rest_bytes == buf + buf_size + ALIGN_SIZE ) {
			return buf;
		}
	}
	return NULL; /* can't realloc */
}

apr_size_t openiam_align_size(apr_size_t sz)
{
	sz = sz + ALIGN_SIZE;
	sz = sz - sz % ALIGN_SIZE;
	return sz;
}
