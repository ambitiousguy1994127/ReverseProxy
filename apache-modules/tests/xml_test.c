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
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "benchmark.h"
#define COOKIE_MIN_SIZE    (256)
#define FILE_BUF_SIZE      (4096)
#define BUF_BLOCK_SIZE (64*1024)
#include "../access/curl_recv_data.h"
#include "../access/parse_soap_xml.h"
#include "../access/parse_soap_str.h"
#include "../access/str_utils.h"
apr_pool_t* main_pool;
apr_file_t* out;

#define ITERATIONS_COUNT (1000)
#define ITERATIONS_COUNT2 (1000)

const char* g_args[]   = { "userId", "authLevel", "proxyURI",        "principal", "token",                                            "tokenType"     };
const char* g_values[] = { "3000",   "1",         "www.example.com", "sysadmin",  "08161b38c3650dba1e65a9d8a53e7128d6c8570f4622c032", "OPENIAM_TOKEN" };
const int count = sizeof(g_args) / sizeof(g_args[0]);

const char* g_service_key_url = "http://lnx06.openiamdemo.com/openiam-esb/idmsrvc/KeyManagementWS";

int save_to_file(apr_pool_t* pool, const char* filename, const char* buffer, size_t size)
{
    apr_file_t* file = NULL;

    apr_file_remove(filename, pool);

    if ( apr_file_open(&file, filename, APR_CREATE | APR_FOPEN_WRITE, APR_OS_DEFAULT, pool) == 0 ) {
        apr_file_write(file, buffer, &size);
        apr_file_close(file);
        return 1;
    } else {
        apr_file_printf(out, "can't save xml file %s", filename);
        return 0;
    }
}

int test_request_args(apr_pool_t* pool)
{
    xmlChar *buffer[count*2];
    xmlChar *buf;
    int i, f, size[count*2], sz;
    char* error_str  = NULL;
    xmlNodePtr xml_node_soap_command;
    const char* soap_command[count*2];

    xml_node_soap_command = create_api_command_xml(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service", &error_str);
    if ( xml_node_soap_command == NULL || error_str ) {
        apr_file_printf(out, "FAIL: test_request_args. Error in create_api_command_xml: %s\n", error_str);
        return 0;
    }

    for ( i = 0; i < count; ++i ) {
        for ( f = 0; f < 2; ++f ) {
            xmlDocDumpFormatMemory(xml_node_soap_command->doc, &buf, &sz, f);
            if ( buf == NULL || sz == 0 ) {
                apr_file_printf(out, "error in xmlDocDumpFormatMemory. buffer is NULL or empty");
                return 0;
            } else {
                apr_pool_cleanup_register(pool, buf, (void *) xmlFree, apr_pool_cleanup_null);
            }
            buffer[i + count*f] = buf;
            size[i + count*f]   = sz;
            save_to_file(pool, apr_pstrcat(pool, "soap/request_xml_", f ? "f_" : "0_", apr_itoa(pool, i), ".xml", NULL), (const char*)buf, sz);
        }

        xmlNewChild(xml_node_soap_command, NULL, BAD_CAST g_args[i], BAD_CAST g_values[i]);
    }

    /* ****************************************************** */

    for ( f = 0; f <= 1; ++f)
    {
        soap_command[0 + f*count] = create_api_command_str(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service", f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 0), ".xml", NULL), soap_command[0 + f*count], strlen(soap_command[0 + f*count]));

        soap_command[1 + f*count] = create_api_command_arg(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                    g_args[0], g_values[0], f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 1), ".xml", NULL), soap_command[1 + f*count], strlen(soap_command[1 + f*count]));

        soap_command[2 + f*count] = create_api_command_arg2(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                    g_args[0], g_values[0],
                                                    g_args[1], g_values[1], f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 2), ".xml", NULL), soap_command[2 + f*count], strlen(soap_command[2 + f*count]));

        soap_command[3 + f*count] = create_api_command_arg3(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                    g_args[0], g_values[0],
                                                    g_args[1], g_values[1],
                                                    g_args[2], g_values[2], f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 3), ".xml", NULL), soap_command[3 + f*count], strlen(soap_command[3 + f*count]));

        soap_command[4 + f*count] = create_api_command_arg4(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                    g_args[0], g_values[0],
                                                    g_args[1], g_values[1],
                                                    g_args[2], g_values[2],
                                                    g_args[3], g_values[3], f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 4), ".xml", NULL), soap_command[4 + f*count], strlen(soap_command[4 + f*count]));

        soap_command[5 + f*count] = create_api_command_arg5(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                    g_args[0], g_values[0],
                                                    g_args[1], g_values[1],
                                                    g_args[2], g_values[2],
                                                    g_args[3], g_values[3],
                                                    g_args[4], g_values[4], f);
        save_to_file(pool, apr_pstrcat(pool, "soap/request_str_", f ? "f_" : "0_", apr_itoa(pool, 5), ".xml", NULL), soap_command[5 + f*count], strlen(soap_command[5 + f*count]));
    }

    for ( i = 0; i < count*2; ++i) {
        if ( strncmp(soap_command[i], buffer[i], size[i]) == 0 ) {
            apr_file_printf(out, "PASS: %d %d request\n", i, size[i]);
        } else {
            apr_file_printf(out, "FAIL: %d %d request\n", i, size[i]);
        }
    }

    return 1;
}

int benchmark_libxml(apr_pool_t* pool, int f)
{
    xmlChar *buffer = NULL;
    int size = 0;
    xmlChar *buffer_get_cookie_key = NULL;
    int size_get_cookie_key = 0;
    xmlChar *buffer_renew = NULL;
    int size_renew = 0;
    char* error_str  = NULL;
    xmlNodePtr xml_node_soap_command_get_cookie_key;
    xmlNodePtr xml_node_soap_command_renew;

    xmlNodePtr xml_node_soap_command = create_api_command_xml(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service", &error_str);
    if ( xml_node_soap_command == NULL || error_str ) {
        apr_file_printf(out, "error in create_api_command_xml: %s\n", error_str);
        return 0;
    }
    xmlNewChild(xml_node_soap_command, NULL, BAD_CAST g_args[0], BAD_CAST g_values[0]);
    xmlNewChild(xml_node_soap_command, NULL, BAD_CAST g_args[1], BAD_CAST g_values[1]);
    xmlNewChild(xml_node_soap_command, NULL, BAD_CAST g_args[2], BAD_CAST g_values[2]);

    xmlDocDumpFormatMemory(xml_node_soap_command->doc, &buffer, &size, f);
    if ( buffer == NULL || size == 0 ) {
        apr_file_printf(out, "error in xmlDocDumpFormatMemory. buffer is NULL or empty\n");
        return 0;
    } else {
        apr_pool_cleanup_register(pool, buffer, (void *) xmlFree, apr_pool_cleanup_null);
    }

    xml_node_soap_command_get_cookie_key = create_api_command_xml(pool, "getCookieKey", "urn:idm.openiam.org/srvc/res/service", &error_str);
    if ( xml_node_soap_command_get_cookie_key == NULL || error_str ) {
        apr_file_printf(out, "error in create_api_command_xml: %s\n", error_str);
        return 0;
    }
    xmlDocDumpFormatMemory(xml_node_soap_command_get_cookie_key->doc, &buffer_get_cookie_key, &size_get_cookie_key, f);
    if ( buffer_get_cookie_key == NULL || size_get_cookie_key == 0 ) {
        apr_file_printf(out, "error in xmlDocDumpFormatMemory. buffer is NULL or empty\n");
        return 0;
    } else {
        apr_pool_cleanup_register(pool, buffer_get_cookie_key, (void *) xmlFree, apr_pool_cleanup_null);
    }

    xml_node_soap_command_renew = create_api_command_xml(pool, "renewToken", "http://service.auth.srvc.idm.openiam.org/", &error_str);
    if ( xml_node_soap_command_renew == NULL || error_str ) {
        apr_file_printf(out, "error in create_api_command_xml: %s\n", error_str);
        return 0;
    }
    xmlNewChild(xml_node_soap_command_renew, NULL, BAD_CAST g_args[3], BAD_CAST g_values[3]);
    xmlNewChild(xml_node_soap_command_renew, NULL, BAD_CAST g_args[4], BAD_CAST g_values[4]);
    xmlNewChild(xml_node_soap_command_renew, NULL, BAD_CAST g_args[5], BAD_CAST g_values[5]);

    xmlDocDumpFormatMemory(xml_node_soap_command_renew->doc, &buffer_renew, &size_renew, f);
    if ( buffer_renew == NULL || size_renew == 0 ) {
        apr_file_printf(out, "error in xmlDocDumpFormatMemory. buffer is NULL or empty\n");
        return 0;
    } else {
        apr_pool_cleanup_register(pool, buffer_renew, (void *) xmlFree, apr_pool_cleanup_null);
    }

    return 1;
}

int benchmark_str(apr_pool_t* pool, int f)
{
    size_t size = 0;
    size_t size_get_cookie_key = 0;
    size_t size_renew = 0;
    const char* soap_command_get_cookie_key;
    const char* soap_command_renew;

    const char* soap_command = create_api_command_arg3(pool,    "federateProxyURI", "urn:idm.openiam.org/srvc/am/service", 
                                                                g_args[0], g_values[0],
                                                                g_args[1], g_values[1],
                                                                g_args[2], g_values[2], f);
    if ( soap_command == NULL ) {
        apr_file_printf(out, "error in create_api_command_str\n");
        return 0;
    }
    size = strlen(soap_command);
    if ( size == 0 ) {
        return 0;
    }

    soap_command_get_cookie_key = create_api_command_str(pool, "getCookieKey", "urn:idm.openiam.org/srvc/res/service", f);
    if ( soap_command_get_cookie_key == NULL ) {
        apr_file_printf(out, "error in create_api_command_str\n");
        return 0;
    }
    size_get_cookie_key = strlen(soap_command_get_cookie_key);
    if ( size_get_cookie_key == 0 ) {
        return 0;
    }

    soap_command_renew = create_api_command_arg3(pool, "federateProxyURI", "urn:idm.openiam.org/srvc/am/service",
                                                       g_args[3], g_values[3],
                                                       g_args[4], g_values[4],
                                                       g_args[5], g_values[5], f);
    if ( soap_command_renew == NULL ) {
        apr_file_printf(out, "error in create_api_command_str\n");
        return 0;
    }
    size_renew = strlen(soap_command_renew);
    if ( size_renew == 0 ) {
        return 0;
    }

    return 1;
}

int benchmark_str_special(apr_pool_t* pool)
{
    size_t size = 0;
    size_t size_get_cookie_key = 0;
    size_t size_renew = 0;
    const char* soap_command_get_cookie_key;
    const char* soap_command_renew;

	const char* soap_command = create_api_command_federate_uri(pool, g_values[0], g_values[1], g_values[2]);
    if ( soap_command == NULL ) {
        apr_file_printf(out, "error in create_api_command_str\n");
        return 0;
    }
    size = strlen(soap_command);
    if ( size == 0 ) {
        return 0;
    }

    soap_command_get_cookie_key = create_api_command_get_cookie_key();
    size_get_cookie_key = strlen(soap_command_get_cookie_key);
    if ( size_get_cookie_key == 0 ) {
        return 0;
    }

    soap_command_renew = create_api_command_renew_token(pool, g_values[3], g_values[4], g_values[5]);
    if ( soap_command_renew == NULL ) {
        apr_file_printf(out, "error in create_api_command_str\n");
        return 0;
    }
    size_renew = strlen(soap_command_renew);
    if ( size_renew == 0 ) {
        return 0;
    }

    return 1;
}

char* get_response_cookie_key(apr_pool_t* pool)
{
    int result = 1;
    long http_code;
    CURLcode ret;
    apr_file_t* file = NULL;
    curl_recv_context_rec context;
    const char* soap_command_get_cookie_key = create_api_command_get_cookie_key();
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;

    context.response_data = 0;
    context.response_capacity = 0;
    context.response_size = 0;
    context.pool = pool;

    curl_easy_setopt(curl, CURLOPT_URL,            g_service_key_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_recv_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &context);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    soap_command_get_cookie_key);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(soap_command_get_cookie_key));

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);

    headers = curl_slist_append(headers, "Content-Type: text/plain");
    if ( headers ) {
        apr_pool_cleanup_register(pool, headers, (void *) curl_slist_free_all, apr_pool_cleanup_null);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    apr_file_printf(out, "request %s\n", soap_command_get_cookie_key);
    if ( (ret = curl_easy_perform(curl)) == CURLE_OK ) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if ( http_code == 200 ) {
            apr_file_printf(out, "recieved %s %d %d\n", context.response_data, context.response_size, strlen(context.response_data));
            if ( apr_file_open(&file, "soap/cookie_key.xml", APR_CREATE | APR_FOPEN_WRITE, APR_OS_DEFAULT, pool) == 0 ) {
                 apr_file_write(file, context.response_data, &context.response_size);
                 apr_file_close(file);
                 file = NULL;
            } else {
                apr_file_printf(out, "can't save soap/cookie_key.xml");
            }
        } else {
            apr_file_printf(out, "http returned %d", http_code);
        }
    } else {
        apr_file_printf(out, "can't send request");
    }
    curl_easy_cleanup(curl);

    return context.response_data;
}

char* get_response_renew_token(apr_pool_t* pool)
{
    int result = 1;
    long http_code;
    CURLcode ret;
    apr_file_t* file = NULL;
    curl_recv_context_rec context;
    const char* soap_command_get_cookie_key = create_api_command_get_cookie_key();
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = NULL;

    context.response_data = 0;
    context.response_capacity = 0;
    context.response_size = 0;
    context.pool = pool;

    curl_easy_setopt(curl, CURLOPT_URL,            g_service_key_url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_recv_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &context);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    soap_command_get_cookie_key);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(soap_command_get_cookie_key));

    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);

    headers = curl_slist_append(headers, "Content-Type: text/plain");
    if ( headers ) {
        apr_pool_cleanup_register(pool, headers, (void *) curl_slist_free_all, apr_pool_cleanup_null);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    apr_file_printf(out, "request %s\n", soap_command_get_cookie_key);
    if ( (ret = curl_easy_perform(curl)) == CURLE_OK ) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if ( http_code == 200 ) {
            apr_file_printf(out, "recieved %s %d %d\n", context.response_data, context.response_size, strlen(context.response_data));
            if ( apr_file_open(&file, "soap/cookie_key.xml", APR_CREATE | APR_FOPEN_WRITE, APR_OS_DEFAULT, pool) == 0 ) {
                 apr_file_write(file, context.response_data, &context.response_size);
                 apr_file_close(file);
                 file = NULL;
            } else {
                apr_file_printf(out, "can't save soap/cookie_key.xml");
            }
        } else {
            apr_file_printf(out, "http returned %d", http_code);
        }
    } else {
        apr_file_printf(out, "can't send request");
    }
    curl_easy_cleanup(curl);

    return context.response_data;
}


char* read_file(apr_pool_t* pool, const char* filename)
{
    apr_finfo_t info;
    apr_file_t* file = NULL;
    char* buff = NULL;
    if ( apr_file_open(&file, filename, APR_FOPEN_READ, APR_OS_DEFAULT, pool) == 0 ) {
        apr_file_info_get (&info, APR_FINFO_SIZE, file);
        if ( info.size > 0 ) {
            buff = apr_palloc(pool, info.size + 1);
            apr_file_read(file, buff, &info.size);
            buff[info.size] = '\0';
        }
    }
    return buff;
}



void test_key_response(apr_pool_t* pool, const char* response)
{
    const char* key = find_return_str(pool, response);
    apr_file_printf(out, "response key is: %s\n", key);
}

void test_key_response_parse_speed(apr_pool_t* pool, char* response)
{
	USES_BENCHMARK;
	size_t i, l;
    const char* key = find_return_str(pool, response);
	l = strlen(key);

    START_BENCHMARK("find_return_str(key_response)");
    for(i = 0; i < ITERATIONS_COUNT*ITERATIONS_COUNT2; ++i) {
    	key = find_return_str(pool, response);
		if ( key == NULL ) {
		    apr_file_printf(out, "FAILED.\n");
			break;
		}
    }
    STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);

    START_BENCHMARK("key_return_str(key_response)");
    for(i = 0; i < ITERATIONS_COUNT*ITERATIONS_COUNT2; ++i) {
    	key = key_return_str(response);
		if ( key == NULL ) {
		    apr_file_printf(out, "FAILED.\n");
			break;
		}
		response[SOAP_KEY_CACHED_INDEX+8+l] = '<';
	}
	STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);

	START_BENCHMARK("find_return_str_with_cached_index(key_response)");
	for(i = 0; i < ITERATIONS_COUNT*ITERATIONS_COUNT2; ++i) {
		key = find_return_str_with_cached_index(pool, response, SOAP_KEY_CACHED_INDEX);
		if ( key == NULL ) {
		    apr_file_printf(out, "FAILED.\n");
			break;
		}
	}
	STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);

}


int benchmark_parse_libxml(apr_pool_t* pool, xmlDocPtr doc)
{
	char* error_str = NULL;
	process_uri_patterns_xml(pool, NULL, doc, &error_str);
	if (error_str) {
		apr_file_printf(out, "error_str = %s\n", error_str);
	}
	return 1;
}

int benchmark_parse_str(apr_pool_t* pool, const char* content)
{
	char* error_str = NULL;
	process_uri_patterns_str(pool, NULL, content, &error_str);
	if (error_str) {
		apr_file_printf(out, "error_str = %s\n", error_str);
	}
	return 1;
}

int benchmark_parse_str_inplace(apr_pool_t* pool, const char* content)
{
	char* error_str = NULL;
	process_uri_patterns_str_inplace(pool, NULL, content, &error_str);
	if (error_str) {
		apr_file_printf(out, "error_str = %s\n", error_str);
	}
	return 1;
}

void test_parse_speed(apr_pool_t* main_pool, char* response)
{
	USES_BENCHMARK;
    size_t i, j;
    apr_pool_t* pool;

	char* c[ITERATIONS_COUNT][ITERATIONS_COUNT2];

	START_BENCHMARK("parse using strstr functions");
	for(i = 0; i < ITERATIONS_COUNT; ++i) {
		apr_pool_create(&pool, main_pool);
		for(j = 0; j < ITERATIONS_COUNT2; ++j) {
			if ( benchmark_parse_str(pool, response) == 0 ) {
				apr_file_printf(out, "error parsing\n");
				goto strstr_end;
			}
		}
		apr_pool_destroy(pool);
	}
strstr_end:
    STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);

	for(i = 0; i < ITERATIONS_COUNT; ++i) {
		for(j = 0; j < ITERATIONS_COUNT2; ++j) {
			c[i][j] = apr_pstrdup(main_pool, response);
		}
	}

	START_BENCHMARK("parse using str inplace functions");
	for(i = 0; i < ITERATIONS_COUNT; ++i) {
		apr_pool_create(&pool, main_pool);
		for(j = 0; j < ITERATIONS_COUNT2; ++j) {
			if ( benchmark_parse_str_inplace(pool, c[i][j]) == 0 ) {
				apr_file_printf(out, "error parsing\n");
				goto strinplace_end;
			}
		}
		apr_pool_destroy(pool);
	}
strinplace_end:
    STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);

	START_BENCHMARK("parse using libxml");
	for(i = 0; i < ITERATIONS_COUNT; ++i) {
		apr_pool_create(&pool, main_pool);
		for(j = 0; j < ITERATIONS_COUNT2; ++j) {
			xmlDocPtr doc = xmlParseMemory(response, strlen(response));
			apr_pool_cleanup_register(pool, doc, (void *) xmlFreeDoc, apr_pool_cleanup_null);
			if ( benchmark_parse_libxml(pool, doc) == 0 ) {
				apr_file_printf(out, "error parsing\n");
				goto libxml_end;
			}
		}
		apr_pool_destroy(pool);
	}
libxml_end:
    STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2);



}





int main(int argc, char** argv)
{
    USES_BENCHMARK
    size_t i, j, f;
    apr_pool_t* pool;

    apr_initialize();
    atexit(apr_terminate);

    apr_pool_create(&main_pool, NULL);
    apr_file_open_stdout(&out, main_pool);

    apr_file_printf(out, "initializing...\n");
    apr_dir_make("soap", APR_OS_DEFAULT, main_pool);
    curl_global_init(CURL_GLOBAL_ALL);

    char* cookie_key_response = read_file(main_pool, "soap/cookie_key.xml");
    if ( cookie_key_response == NULL) cookie_key_response = get_response_cookie_key(pool);
 
    test_key_response(main_pool, cookie_key_response);
	test_key_response_parse_speed(main_pool, cookie_key_response);

    char* federation_response = read_file(main_pool, "federate.txt");
	test_parse_speed(main_pool, federation_response);

    test_request_args(main_pool);

    for (f = 0; f <= 1; ++f ) {
        apr_file_printf(out, "format = %d\n", f);

        START_BENCHMARK("libxml benchmark");
        for(i = 0; i < ITERATIONS_COUNT; ++i) {
            apr_pool_create(&pool, main_pool);
            for(j = 0; j < ITERATIONS_COUNT2; ++j) {
                if ( benchmark_libxml(pool, f) == 0 ) {
                    apr_file_printf(out, "error in benchmark_libxml\n");
                    goto libxml_end;
                }
            }
            apr_pool_destroy(pool);
        }
libxml_end:
        STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2*3);

        START_BENCHMARK("strstr benchmark");
        for(i = 0; i < ITERATIONS_COUNT; ++i) {
            apr_pool_create(&pool, main_pool);
            for(j = 0; j < ITERATIONS_COUNT2; ++j) {
                if ( benchmark_str(pool, f) == 0 ) {
                    apr_file_printf(out, "error in benchmark_str\n");
                    goto strstr_end;
                }
            }
            apr_pool_destroy(pool);
        }
strstr_end:
        STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2*3);
    }

    apr_file_printf(out, "special create functions\n");
    START_BENCHMARK("strstr special benchmark");
    for(i = 0; i < ITERATIONS_COUNT; ++i) {
        apr_pool_create(&pool, main_pool);
        for(j = 0; j < ITERATIONS_COUNT2; ++j) {
            if ( benchmark_str_special(pool) == 0 ) {
                apr_file_printf(out, "error in benchmark_str_special\n");
                goto strspecial_end;
            }
        }
        apr_pool_destroy(pool);
    }
strspecial_end:
    STOP_BENCHMARK(ITERATIONS_COUNT*ITERATIONS_COUNT2*3);


    apr_pool_destroy(main_pool);

    return EXIT_SUCCESS;
}


void process_uri_pattern(void* p, int pattern_type, apr_array_header_t* values)
{
/*	apr_file_printf(out, "%d, %ld\n", pattern_type, values->nelts); */
}
