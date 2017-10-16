/*
 * Module for parsing SOAP responses from OpenIAM Authenticaton
 * Authors: Evgeniy Sergeev, OpenIAM LLC
 */

#define URI_PATTERN_METATYPE_COOKIE   (1)
#define URI_PATTERN_METATYPE_HEADER   (2)
#define URI_PATTERN_METATYPE_FORM     (3)
#define URI_PATTERN_METATYPE_URI      (4)

apr_status_t process_uri_pattern(void* p, int pattern_type, apr_array_header_t* values);
