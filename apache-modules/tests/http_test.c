#include <stdio.h>
#ifdef __i386__
typedef __off64_t off64_t;
#endif
#include <apr-1/apr.h>
#include <apr-1/apr_pools.h>
#include <apr-1/apr_file_io.h>
#include <apr-1/apr_strings.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <assert.h>
#define COOKIE_MIN_SIZE    (256)
#define FILE_BUF_SIZE      (4096)
#define BUF_BLOCK_SIZE (64*1024)
#include "../access/curl_recv_data.h"
#include "benchmark.h"

static char* s_OK   = "[  OK  ]\n";
static char* s_FAIL = "[ FAIL ]\n";
static char* s_lnx01 = "http://lnx01.openiamdemo.com:2443";
static char* s_lnx06 = "http://lnx06.openiamdemo.com";
static char* s_login_uri = "/idp/login.html";
static char* s_post_data = "login=sysadmin&password=passwd00&postbackURL=http%3A%2F%2Flnx06.openiamdemo.com%2Fselfservice%2F";

static char* s_uris[] = {
"/idp/changePassword.html",
"/idp/unlockPassword.html",
"/selfservice",
"/selfservice/menu/IDQUEST"
"/selfservice/menu/SELFSERVICE_MYAPPS",
"/selfservice/menu/SELF_USERSUMMARY",
"/selfservice/menu/SELF_USERIDENTITY",
"/selfservice/menu/NEWUSER-NOAPPRV",
"/selfservice/menu/SELFSERVICE_MYINFO",
"/webconsole",
"/webconsole/menu/USER",
"/webconsole/menu/ORG",
"/webconsole/menu/ORG_SEARCH",
"/webconsole/menu/NEW_ORG",
"/webconsole/menu/SECURITY_GROUP",
"/webconsole/menu/AM_PROV_SEARCH_CHILD",
"/webconsole/menu/CONTENT_PROV_SEARCH_CHILD",
"/webconsole/menu/SECURITY_ROLE",
"/webconsole/menu/SECURITY_RES",
"/webconsole/menu/PROVCONNECT",
"/webconsole/menu/MNGSYS",
"/webconsole/menu/TEMPLATE_SEARCH_CHILD",
"/webconsole/menu/CUSTOM_FIELD_SEARCH_CHILD",
/* "https://mail.google.com/a/openiamdemo.com",
"https://openiam-dev-ed.my.salesforce.com/",
"https://sso.services.box.net/sp/startSSO.ping?PartnerIdpId=http://lnx06.openiamdemo.com/idp/SAMLLogin.html",
"http://www.foobar.com/",
"https://login.microsoftonline.com/" */
};

static char  s_cookie_name[] = "OPENIAM_AUTH_TOKEN";
static char  s_set_cookie[]  = "Set-Cookie:";

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#define ITERATIONS_COUNT (5)

#define DO_AUTH(url) do { apr_file_printf(out, "authentication...                      "); if ( do_login(context, login_lnx01) ) { printf(s_OK); } else { printf(s_FAIL); return 1; } } while (0);

apr_pool_t* main_pool;
apr_file_t* out;
apr_file_t* results;

typedef struct {
	/* !!! FIRST FIELDS SHOULD BE THE SAME AS IN curl_recv_context_rec in curl_recv_data.h !!! */
	apr_pool_t *pool;
	char*       response_data;
	size_t      response_size;
	size_t      response_capacity;
	/* end compatability */
	CURL*       curl;
	struct curl_slist* headers;
	char*       auth_cookie;
	size_t      auth_cookie_capacity;
} context_t;

static size_t curl_recv_header( char *ptr, size_t size, size_t nmemb, context_t *context)
{
    const size_t chunk_size = size * nmemb;

    if ( chunk_size > sizeof(s_set_cookie) && strncasecmp(ptr, s_set_cookie, sizeof(s_set_cookie) - 1) == 0 ) {
        ptr[chunk_size-1] = '\0';        
        char* openiam_auth_token = strstr(ptr, s_cookie_name);
        if ( openiam_auth_token ) {
            char* endp = strchr(openiam_auth_token, ';');
            if ( endp ) {
                *endp = '\0';
            }
            size_t length = strlen(openiam_auth_token);
            if ( length ) {
                length += 1;
                if ( length > context->auth_cookie_capacity ) {
                    size_t new_capacity = length + COOKIE_MIN_SIZE - length % COOKIE_MIN_SIZE;    
                    context->auth_cookie = apr_palloc(context->pool, new_capacity); 
                    context->auth_cookie_capacity = new_capacity;
                }
                memcpy(context->auth_cookie, openiam_auth_token, length);
            }
        }
    }

    return chunk_size;
}

static void set_curl_params_request(context_t* context, char* url)
{
    curl_easy_setopt(context->curl, CURLOPT_URL, url);
    curl_easy_setopt(context->curl, CURLOPT_HEADERFUNCTION, curl_recv_header);
    curl_easy_setopt(context->curl, CURLOPT_HEADERDATA,     context);
    curl_easy_setopt(context->curl, CURLOPT_WRITEFUNCTION,  curl_recv_data);
    curl_easy_setopt(context->curl, CURLOPT_WRITEDATA,      context);

    if ( context->auth_cookie ) {
        curl_easy_setopt(context->curl, CURLOPT_COOKIE, context->auth_cookie);
    }

    if ( context->headers ) {
        curl_easy_setopt(context->curl, CURLOPT_HTTPHEADER, context->headers);
    }

    curl_easy_setopt(context->curl, CURLOPT_FOLLOWLOCATION, 1);
    /* curl_easy_setopt(context->curl, CURLOPT_VERBOSE, 1); */
}

static void set_curl_params_for_login(context_t* context, char* url, char* request_body)
{
    size_t request_body_size = request_body ? strlen(request_body) : 0;

    if ( request_body && request_body_size ) {
        curl_easy_setopt(context->curl, CURLOPT_POSTFIELDS,    request_body);
        curl_easy_setopt(context->curl, CURLOPT_POSTFIELDSIZE, request_body_size);
        context->headers = curl_slist_append(context->headers, "Content-Type: application/x-www-form-urlencoded");
    }

    set_curl_params_request(context, url);
    
    curl_easy_setopt(context->curl, CURLOPT_FOLLOWLOCATION, 0);
}

static void clean_curl_after_request(context_t* context)
{
    if ( context->headers ) {
        curl_slist_free_all(context->headers);
        context->headers = NULL;
    }
    curl_easy_reset(context->curl);

    if ( context->response_data ) {
        context->response_data[0] = '\0';
        context->response_size = 0;
    }    
}

static void do_clear_auth_cookie(context_t* context)
{
    if ( context->auth_cookie ) {
        context->auth_cookie[0] = '\0';
    }
}

static int do_login(context_t* context, char* login_url)
{
    long http_code;
    CURLcode ret;

    set_curl_params_for_login(context, login_url, s_post_data);
    if ( (ret = curl_easy_perform(context->curl)) == CURLE_OK ) {
        curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &http_code);
        if ( http_code == 302 || http_code == 200 ) {
        /*    apr_file_printf(out, "cookie=%s\n", context->auth_cookie);
            apr_file_printf(out, "content=%s\n", context->response_data);  */
        } else {
            apr_file_printf(out, "http returned %ld", http_code); 
	    return 0;
        }
    } else {
        apr_file_printf(out, "curl can't perform request errcode=%d", ret); 
	return 0;
    }
    clean_curl_after_request(context);
    
    return 1;
}

static void done_context(context_t* context)
{
    if ( context->curl ) {
    	curl_easy_cleanup(context->curl);
	context->curl = NULL;
    }
}

static context_t* init_context(apr_pool_t* pool)
{
    context_t* context;

    context = apr_pcalloc(pool, sizeof(*context));
    assert(context);

    context->curl = curl_easy_init();
    assert(context->curl);

    apr_pool_create(&context->pool, NULL);
    assert(context->pool);

    return context;
}


char* file_name_for_uri(apr_pool_t *pool, const char* url)
{
	char* str = apr_pstrdup(pool, url);
	char* c = str;
	while ( (c = strpbrk(c, ":/@&?\\%.")) ) {
		*c = '_';
	}
	return str;
}

static int check_url(context_t* context, char* url, int grab)
{
	int result = 1;
	long http_code;
	CURLcode ret;
	apr_file_t* file = NULL;
	char* filename = apr_pstrcat(context->pool, "content/", file_name_for_uri(context->pool, url), ".html", NULL);
	char* buf = apr_palloc(context->pool, FILE_BUF_SIZE);
	apr_size_t sz, i, j;
	char* str = NULL;

	set_curl_params_request(context, url);

	if ( (ret = curl_easy_perform(context->curl)) == CURLE_OK ) {
		curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &http_code);
		if ( http_code == 200 ) {
			if ( grab ) {
				apr_file_printf(out, "saving file %s...", filename);
				if ( apr_file_open(&file, filename, APR_CREATE | APR_FOPEN_WRITE, APR_OS_DEFAULT, context->pool) == 0 ) {
					apr_file_printf(file, "%s", context->response_data);
					apr_file_close(file);
					file = NULL;
				} else {
					apr_file_printf(out, "can't save file");
					result = 0;
				}
			} else {
				apr_file_printf(out, "checking file %s...", filename);
				if ( apr_file_open(&file, filename, APR_FOPEN_READ, APR_OS_DEFAULT, context->pool) == 0 ) {
					str = context->response_data;
					do {
						sz = FILE_BUF_SIZE;
						if ( apr_file_read(file, buf, &sz) == APR_EOF ) {
							break;
						}
						if ( sz == 0 ) {
							apr_file_printf(out, "failed to read file");
							result = 0;
						} else {
							apr_file_printf(out, ".");
						}
						if ( strncmp(str, buf, sz) != 0 ) {
							apr_file_printf(out, "content different:\n%s\n", str);
							
							j = 1000;
							for (i = 0; i < min( strlen(str), sz); ++i) {
								if (str[i] != buf[i]) {
									apr_file_printf(out, "at position:%ld\n", i);
									j --;
									if ( j == 0 ) {
										break;
									}
								}
							}
							if ( file ) apr_file_close(file);
							file = NULL;
							filename = apr_pstrcat(context->pool, "content/", file_name_for_uri(context->pool, url), ".bad", NULL);
							apr_file_printf(out, "saving diff to %s...", filename);
							if ( apr_file_open(&file, filename, APR_CREATE | APR_FOPEN_WRITE, APR_OS_DEFAULT, context->pool) == 0 ) {
								apr_file_printf(file, "%s", context->response_data);
								apr_file_close(file);
								file = NULL;
								apr_file_printf(out, "done saving diff.");
								break;
							} else {
								apr_file_printf(out, "can't save bad file");
								break;
							}
							
							result = 0;
							break;
						}
						str += sz;
					} while ( sz );
					if ( file ) apr_file_close(file);
					file = NULL;
				} else {
					apr_file_printf(out, "can't load file");
					result = 0;
				}
			}
		} else {
			apr_file_printf(out, "http returned %ld", http_code); 
			result = 0;
		}
	} else {
		apr_file_printf(out, "curl can't perform request errcode=%d", ret); 
		result = 0;
	}
	clean_curl_after_request(context);

	return result;
}

static int grab_urls_list(context_t* context, apr_array_header_t* urls)
{
	apr_dir_make("content", APR_OS_DEFAULT, context->pool);

    int i;
    for ( i = 0; i < urls->nelts; ++i ) {
        char* url = ((char**)(urls->elts))[i];
        if ( check_url(context, url, 1) ) { 
            printf(s_OK); 
        } else {
            printf(s_FAIL); 
		    return 0;
        }
    }
    return 1;
}

static int check_urls_list(context_t* context, apr_array_header_t* urls)
{
    int i;
    for ( i = 0; i < urls->nelts; ++i ) {
        char* url = ((char**)(urls->elts))[i];
        if ( check_url(context, url, 0) ) { 
            printf(s_OK); 
        } else {
            printf(s_FAIL); 
		    return 0;
        }
    }
    return 1;
}

static int do_test_on_url(context_t* context, char* url)
{
    long http_code;
    CURLcode ret;

    set_curl_params_request(context, url);

    if ( (ret = curl_easy_perform(context->curl)) == CURLE_OK ) {
        curl_easy_getinfo(context->curl, CURLINFO_RESPONSE_CODE, &http_code);
        if ( http_code == 200 ) {
        /*    apr_file_printf(out, "cookie=%s\n", context->auth_cookie);
            apr_file_printf(out, "content=%s\n", context->response_data);  */
        } else {
            apr_file_printf(out, "http returned %ld", http_code); 
	    return 0;
        }
    } else {
        apr_file_printf(out, "curl can't perform request errcode=%d", ret); 
	return 0;
    }
    clean_curl_after_request(context);
    
    return 1;
}

static int do_test_on_urls_list(context_t* context, apr_array_header_t* urls)
{
    int i;
    for ( i = 0; i < urls->nelts; ++i ) {
        char* url = ((char**)(urls->elts))[i];
        if ( do_test_on_url(context, url) ) { 
            //printf(s_OK); 
        } else {
            printf(s_FAIL); 
	    return 0;
        }
    }
    return 1;
}

static void iterate_logins(context_t* context, char* login_url, size_t count)
{
    size_t i;
    size_t delta = count / 10;
    if ( delta == 0 ) delta = 1;

    for ( i = 0; i < count; ++i ) {
        do_login(context, login_url);
        do_clear_auth_cookie(context);
        if ( i && i % delta == 0 ) {
            apr_file_printf(out, "make %ld logins\n", i);
        }
    }
}

static void iterate_urls(context_t* context, apr_array_header_t* urls, size_t count)
{
    int i;
    int delta = count / 10;
    if ( delta == 0 ) delta = 1;

    for ( i = 0; i < count; ++i ) {
        if ( do_test_on_urls_list(context, urls) == 0)
		{
            apr_file_printf(out, "invalid response");
		    return;
		}
        if ( i && i % delta == 0 ) {
            apr_file_printf(out, "make %d iterations\n", i);
        }
    }
}

int main(int argc, char** argv)
{
	/* local vars */
    USES_BENCHMARK
    double in_module;
    context_t  *context;
    int i;
    char* login_lnx01;
    char* login_lnx06;

	/* common initializations */
    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&main_pool, NULL);
    apr_file_open_stdout(&out, main_pool);

    apr_file_printf(out,         "initializing curl...                  ");
    curl_global_init(CURL_GLOBAL_ALL);

	/* create context */
    context = init_context(main_pool);
    if ( context == NULL ) {
        printf(s_FAIL);
        return 1;
    } else {
        apr_pool_cleanup_register(main_pool, context, (void *) done_context, apr_pool_cleanup_null);
	    printf(s_OK);
    }
    
    /* fix urls lists */
    login_lnx01 = apr_pstrcat(main_pool, s_lnx01, s_login_uri, NULL);
    login_lnx06 = apr_pstrcat(main_pool, s_lnx06, s_login_uri, NULL);

    int count = sizeof(s_uris) / sizeof(s_uris[0]);
    apr_file_printf(out, "count = %d\n", count);
    apr_array_header_t* urls01 = apr_array_make(main_pool, count, sizeof(char*));
    apr_array_header_t* urls06 = apr_array_make(main_pool, count, sizeof(char*));

    for ( i = 0; i < count; ++i ) {
    	if ( strstr(s_uris[i], "://") == NULL ) {
        	*(char**)apr_array_push(urls01) = apr_pstrcat(main_pool, s_lnx01, s_uris[i], NULL);
			*(char**)apr_array_push(urls06) = apr_pstrcat(main_pool, s_lnx06, s_uris[i], NULL);
        } else {
        	*(char**)apr_array_push(urls01) = s_uris[i];
			*(char**)apr_array_push(urls06) = s_uris[i];
        }
    }

	if ( argc == 2 ) {
		if (strcasecmp(argv[1], "-g") == 0 ) {
			apr_file_printf(out, "generating pages...                   ");
			/* generating pages */
			DO_AUTH(login_lnx01);
			grab_urls_list(context, urls01);
			
			DO_AUTH(login_lnx06);
			grab_urls_list(context, urls06);
			return 0;
		} else if (strcasecmp(argv[1], "-c") == 0 ) {
			apr_file_printf(out, "checking pages...                   ");
			/* generating pages */
			DO_AUTH(login_lnx01);
			check_urls_list(context, urls01);
			
			DO_AUTH(login_lnx06);
			check_urls_list(context, urls06);
			return 0;
		}
	}
	
	/* benchmarking */

	DO_AUTH(login_lnx01);

    START_BENCHMARK("lnx01 urls");    
    iterate_urls(context, urls01, ITERATIONS_COUNT);
    STOP_BENCHMARK(ITERATIONS_COUNT*count);
    in_module = delta;

    START_BENCHMARK("lnx01 logins");    
    iterate_logins(context, login_lnx01, ITERATIONS_COUNT);
    STOP_BENCHMARK(ITERATIONS_COUNT);

    START_BENCHMARK("lnx06 logins");    
    iterate_logins(context, login_lnx06, ITERATIONS_COUNT);
    STOP_BENCHMARK(ITERATIONS_COUNT);

	DO_AUTH(login_lnx06);

    START_BENCHMARK("lnx06 urls");    
    iterate_urls(context, urls06, ITERATIONS_COUNT);
    STOP_BENCHMARK(ITERATIONS_COUNT*count);
    in_module -= delta;
    in_module /= (ITERATIONS_COUNT*count);
    apr_file_printf(out, "in module = %g\n", in_module);

	/* finalization */

    apr_pool_destroy(main_pool);
    
    return EXIT_SUCCESS;
}
