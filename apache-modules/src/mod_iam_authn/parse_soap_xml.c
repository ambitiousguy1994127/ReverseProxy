/*
 * Module for parsing SOAP responses from OpenIAM Authenticaton
 * Authors: Evgeniy Sergeev, OpenIAM LLC
 */

#include "parse_soap_xml.h"
#include <apr_strings.h>
#include "iam_errors.h"
#include "str_utils.h"
#include "debug_dump_options.h"

/* URI Patterns */
static const char s_spring_bean_name[]     = "springBeanName";
static const char s_request_param_cookie[] = "cookieURIPatternRule";
static const char s_request_param_header[] = "headerURIPatternRule";
static const char s_request_param_form[]   = "formPostURIPatternRule";
static const char s_request_param_uri[]    = "requestParamURIPatternRule";

#define KEYNAME_METATYPE                   "metaType"
#define KEYNAME_VALUELIST                  "valueList"

#define KEYNAME_KEY                        "key"
#define KEYNAME_VALUE                      "value"
#define KEYNAME_PROPAGATE                  "propagate"

#define PROPAGATE_YES                      "true"
#define PROPAGATE_NO                       NULL

xmlNodePtr create_api_command_xml(apr_pool_t *pool, const char *command_name, const char *command_xml_namespace, char** error_str)
{
	xmlDocPtr xml_doc_soap_request = xmlNewDoc(BAD_CAST "1.0");
	if ( xml_doc_soap_request == NULL ) {
		if (error_str) *error_str = "error then creating new xml document";
		return NULL;
	}
	apr_pool_cleanup_register(pool, xml_doc_soap_request, (void *) xmlFreeDoc, apr_pool_cleanup_null);
	xmlNodePtr xml_node_soap_envelope = xmlNewNode(NULL, BAD_CAST "soapenv:Envelope");
	if ( xml_node_soap_envelope == NULL ) {
		if (error_str) *error_str = "error in creating new node";
		return NULL;
	}
	xmlNewProp(xml_node_soap_envelope, BAD_CAST "xmlns:soapenv", BAD_CAST "http://schemas.xmlsoap.org/soap/envelope/");
	xmlNewProp(xml_node_soap_envelope, BAD_CAST "xmlns:ser", BAD_CAST command_xml_namespace);
	xmlDocSetRootElement(xml_doc_soap_request, xml_node_soap_envelope);
	xmlNewChild(xml_node_soap_envelope, NULL, BAD_CAST "soapenv:Header", NULL);
	xmlNodePtr xml_node_soap_body = xmlNewChild(xml_node_soap_envelope, NULL, BAD_CAST "soapenv:Body", NULL);
	return xmlNewChild(xml_node_soap_body, NULL, BAD_CAST apr_pstrcat(pool, "ser:", command_name, NULL), NULL);
}

int response_status_xml(apr_pool_t *pool, xmlNodePtr xml_node_response_return, char** error_str)
{
	xmlChar *xml_string_response_status = xmlGetProp(xml_node_response_return, BAD_CAST "status");
	if ( xml_string_response_status == NULL ) {
		if (error_str) *error_str = "No value property \"status\" found in return element";
		return 0;
	}
	apr_pool_cleanup_register(pool, xml_string_response_status, (void *) xmlFree, apr_pool_cleanup_null);
	int isSuccess = xmlStrEqual(xml_string_response_status, BAD_CAST "success");
	if ( !isSuccess ) {
		return 0;
	}
	return 1;
}

xmlNodeSetPtr find_nodes_xml(apr_pool_t *pool, xmlDocPtr xml_doc, const char *node_name, char** error_str)
{
	if ( xml_doc == NULL || node_name == NULL ) {
		if (error_str) *error_str = "Invalid arguments in find_nodes_xml";
		return NULL;
	}
	xmlXPathContext *xml_response_xpath_ctx = xmlXPathNewContext(xml_doc);
	if ( xml_response_xpath_ctx == NULL ) {
		if (error_str) *error_str = "Failed to initialize XPath";
		return NULL;
	}
	apr_pool_cleanup_register(pool, xml_response_xpath_ctx, (void *) xmlXPathFreeContext, apr_pool_cleanup_null);
	xmlXPathObject *xml_response_xpath_obj = xmlXPathEvalExpression(BAD_CAST node_name, xml_response_xpath_ctx);
	if ( xml_response_xpath_obj == NULL ) {
		if (error_str) *error_str = "Internal XPath error in xmlXPathEvalExpression";
		return NULL;
	}
	apr_pool_cleanup_register(pool, xml_response_xpath_obj, (void *) xmlXPathFreeObject, apr_pool_cleanup_null);
	xmlNodeSetPtr xml_response_eval_nodes = xml_response_xpath_obj->nodesetval;
	if ( xmlXPathNodeSetIsEmpty(xml_response_eval_nodes) ) {
		return NULL;
	}
	return xml_response_eval_nodes;
}

xmlNodePtr find_node_xml(apr_pool_t *pool, xmlDocPtr xml_doc, const char *node_name, char** error_str)
{
	xmlNodeSetPtr xml_response_eval_nodes = find_nodes_xml(pool, xml_doc, node_name, error_str);
	if ( xml_response_eval_nodes ) {
		return xml_response_eval_nodes->nodeTab[0];
	}
	return NULL;
}

char* extract_element_xml(apr_pool_t *pool, xmlDocPtr xml_doc, const char* name, char** error_str)
{
	xmlNodePtr xml_node_response_token = find_node_xml(pool, xml_doc, name, error_str);
	if ( xml_node_response_token == NULL ) {
		if (error_str) *error_str = "Element not found";
		return NULL;
	}
	xmlChar *xml_string_response_token = xmlNodeGetContent(xml_node_response_token);
	if ( xml_string_response_token == NULL ) {
		if (error_str) *error_str = "Element is empty";
		return NULL;
	}
	apr_pool_cleanup_register(pool, xml_string_response_token, (void *) xmlFree, apr_pool_cleanup_null);
	return (char*)xml_string_response_token;
}

int extract_uri_pattern_xml(apr_pool_t *pool, xmlNodePtr xml_node, apr_array_header_t** values)
{
	xmlNodePtr child = xml_node->children;
	int pattern_type = 0;
	while ( child ) {
		if ( strcmp((char*)child->name, KEYNAME_METATYPE) == 0 ) {
			xmlNodePtr subchild = child->children;
			while ( subchild ) {
				if ( subchild->name && strcmp((const char*)subchild->name, s_spring_bean_name) ) {
					const char *item_spring_bean_name = (const char*)xmlNodeGetContent(subchild);
					if (item_spring_bean_name) {
						apr_pool_cleanup_register(pool, item_spring_bean_name, (void *) xmlFree, apr_pool_cleanup_null);
						/* TODO: bsearch here */
						if ( strcmp (item_spring_bean_name, s_request_param_cookie) == 0 ) {
							pattern_type = URI_PATTERN_METATYPE_COOKIE;
						} else if ( strcmp (item_spring_bean_name, s_request_param_header) == 0 ) {
							pattern_type = URI_PATTERN_METATYPE_HEADER;
						} else if ( strcmp (item_spring_bean_name, s_request_param_form) == 0 ) {
							pattern_type = URI_PATTERN_METATYPE_FORM;
						} else if ( strcmp (item_spring_bean_name, s_request_param_uri) == 0 ) {
							pattern_type = URI_PATTERN_METATYPE_URI;
						}
						if ( pattern_type ) {
							child = child->next;
							break;
						}
					}
				}
				subchild = subchild->next;
			}
		}
		if ( child ) {
			if ( strcmp((char*)child->name, KEYNAME_VALUELIST) == 0 ) {
				char* key_name   = NULL;
				char* item_value = "";
				char* propagate  = PROPAGATE_NO;

				xmlNodePtr subchild = child->children;
				while ( subchild ) {
					if ( subchild->name ) {
						if ( strcmp((char*)subchild->name, KEYNAME_KEY) == 0 ) {
							key_name = (char*)xmlNodeGetContent(subchild);
							if ( key_name ) {
								apr_pool_cleanup_register(pool, key_name, (void *) xmlFree, apr_pool_cleanup_null);
							}
						} else if ( strcmp((char*)subchild->name, KEYNAME_VALUE) == 0 ) {
							char *value = (char*)xmlNodeGetContent(subchild);
							if ( value ) {
								apr_pool_cleanup_register(pool, value, (void *) xmlFree, apr_pool_cleanup_null);
								item_value = value;
							}
						} else if ( strcmp((char*)subchild->name, KEYNAME_PROPAGATE) == 0 ) {
							char *value = (char*)xmlNodeGetContent(subchild);
							if ( value ) {
								apr_pool_cleanup_register(pool, value, (void *) xmlFree, apr_pool_cleanup_null);
								if ( strcmp(value, "true") == 0 ) {
									propagate = PROPAGATE_YES;
								}
							}
						}
					}
					subchild = subchild->next;
				}

				if ( key_name && item_value ) {
					if ( *values == NULL ) {
						*values = apr_array_make(pool, 20, sizeof(const char*));
					} 
					*((char**)apr_array_push(*values)) = key_name;
					*((char**)apr_array_push(*values)) = ( pattern_type == URI_PATTERN_METATYPE_URI ) 
										? iam_escape_uri(pool, item_value)
										: item_value;
					*((char**)apr_array_push(*values)) = propagate;
				}

			}
			child = child->next;
		}
	}
	return pattern_type;
}

apr_status_t process_uri_patterns_xml(apr_pool_t *pool, void *r, xmlDocPtr xml_doc, char** error_str)
{
	int i;
	int pattern_type;
	xmlNodePtr xml_rule_item;
	apr_array_header_t *values = NULL;
	xmlNodeSetPtr xml_rule_nodes = find_nodes_xml(pool, xml_doc, "//ruleTokenList", error_str);

	if ( xml_rule_nodes ) {
		for ( i = 0; i < xml_rule_nodes->nodeNr; ++i ) {
			xml_rule_item = xml_rule_nodes->nodeTab[i];
			if ( xml_rule_item ) {
				pattern_type = extract_uri_pattern_xml(pool, xml_rule_item, &values);
				if ( pattern_type && values ) {
					apr_status_t ret = process_uri_pattern(r, pattern_type, values);
					if ( ret != APR_SUCCESS ) {
						return ret;
					}
					/* apr_array_clear(values); */
					values = NULL;
				}
			}
		}
	}
	return APR_SUCCESS;
}

