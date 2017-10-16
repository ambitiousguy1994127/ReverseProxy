/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Substitute utils for OpenIAM Module
 * based on mod_substitute.c from apache 2.2
 * Authors: Evgeniy Sergeev, OpenIAM LLC
 */

typedef struct subst_pattern_t {
	const apr_strmatch_pattern *pattern;
	const ap_regex_t *regexp;
	const char *replacement;
	apr_size_t replen;
	apr_size_t patlen;
	int flatten;
} subst_pattern_t;

typedef struct {
	apr_bucket_brigade *linebb;
	apr_bucket_brigade *linesbb;
	apr_bucket_brigade *passbb;
	apr_bucket_brigade *pattbb;
	apr_pool_t *tpool;
} substitute_module_ctx;

const char*  iam_subst_set_pattern(apr_pool_t *pool, apr_array_header_t *patterns, const char *line);
apr_status_t iam_substitute(ap_filter_t *f, apr_bucket_brigade *bb, apr_array_header_t *patterns);
