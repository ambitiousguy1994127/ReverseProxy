/*
 * Module for parsing SOAP responses from OpenIAM Authenticaton
 * Authors: Evgeniy Sergeev, OpenIAM LLC
 */
#ifndef PARSE_SOAP_XML_H
#define PARSE_SOAP_XML_H

#include <stdio.h>
#ifdef __i386__
typedef __off64_t off64_t;
#endif
#include <apr.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "parse_soap.h"

xmlNodePtr create_api_command_xml(apr_pool_t *pool, const char *command_name, const char *command_xml_namespace, char** error_str);

int           response_status_xml(apr_pool_t *pool, xmlNodePtr xml_node_response_return,       char** error_str);
xmlNodeSetPtr find_nodes_xml     (apr_pool_t *pool, xmlDocPtr  xml_doc, const char *node_name, char** error_str);
xmlNodePtr    find_node_xml      (apr_pool_t *pool, xmlDocPtr  xml_doc, const char *node_name, char** error_str);
char*         extract_element_xml(apr_pool_t *pool, xmlDocPtr  xml_doc, const char* name,      char** error_str);

apr_status_t  process_uri_patterns_xml(apr_pool_t* pool, void *r, xmlDocPtr xml_doc, char** error_str);

#endif
