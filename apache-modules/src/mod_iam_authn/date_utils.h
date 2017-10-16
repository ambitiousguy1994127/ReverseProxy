/* date_utils.h
 * Author: Evgeniy Sergeev, <evgeniy.sereev@gmail.com> OpenIAM LLC
 */

#include <apr_strings.h>
#include <apr_date.h>

char*      convert_date_from_soap_to_rfc822(apr_pool_t* pool, const char* soap_datetime);
apr_time_t convert_date_from_soap_to_apr_time(const char* soap_datetime);

