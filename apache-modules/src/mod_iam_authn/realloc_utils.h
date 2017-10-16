/*
 * Author:  Evgeniy Sergeev, OpenIAM LLC
 */
#ifndef __OPENIAM_TABLE_UTILS_H__
#define __OPENIAM_TABLE_UTILS_H__

#include <apr.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include <apr_pools.h>
#include <stdio.h>

void* openiam_realloc(apr_pool_t *pool, void *buf, apr_size_t buf_size, apr_size_t new_size);
apr_size_t openiam_align_size(apr_size_t sz);

#endif
