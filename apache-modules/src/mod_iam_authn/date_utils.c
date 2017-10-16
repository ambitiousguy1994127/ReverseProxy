/* date_utils.c
 * Author: Evgeniy Sergeev, <evgeniy.sereev@gmail.com> OpenIAM LLC
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include <apr_date.h>

#include <stdio.h>

/* SOAP date example: 2013-02-19T21:14:25.741-03:00 */
/* SOAP date example: 2015-08-07T20:05:14Z */
/* SOAP date example: 2015-08-07T20:05:11.784Z */


/* TODO:Refactor next two functions */
char* convert_date_from_soap_to_rfc822(apr_pool_t* pool, const char* soap_datetime)
{
	struct apr_time_exp_t t;
	memset(&t, 0, sizeof(t));
	char z_c = 0;
	char c = 0;
	int z_H = 0;
	int z_M = 0;
	/* SOAP date example: 2013-02-19T21:14:25.741-03:00 */
	if ( soap_datetime == NULL ) {
		return NULL;
	}

	if ( soap_datetime[0] == '-' ) {
		return NULL;
	}
	if ( strchr(soap_datetime, 'z') || strchr(soap_datetime, 'Z') ) {
		sscanf(soap_datetime, "%d-%d-%dT%d:%d:%d.%d%c",
						  &t.tm_year, &t.tm_mon, &t.tm_mday,
						  &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_usec, &c);
		t.tm_gmtoff = 0;
	} else {
		sscanf(soap_datetime, "%d-%d-%dT%d:%d:%d.%d%c%d:%d",
						  &t.tm_year, &t.tm_mon, &t.tm_mday,
						  &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_usec,
						  &z_c, &z_H, &z_M);
		t.tm_gmtoff = ((z_H * 60 + z_M) * 60); // convert H:M to seconds from gmt
		if ( z_c == '-' ) {
			t.tm_gmtoff = -t.tm_gmtoff;
		}
	}
	t.tm_mon --;
	t.tm_year = t.tm_year - 1900;
	t.tm_usec *= 1000;
	apr_time_t apr_time;
	apr_time_exp_gmt_get(&apr_time, &t);
	char* rfc_date = apr_palloc(pool, APR_RFC822_DATE_LEN);
	if ( apr_rfc822_date(rfc_date, apr_time) != APR_SUCCESS ) {
		return NULL;
	}
	return rfc_date;
}

apr_time_t convert_date_from_soap_to_apr_time(const char* soap_datetime)
{
	struct apr_time_exp_t t;
	memset(&t, 0, sizeof(t));
	char z_c = 0;
	char c = 0;
	int z_H = 0;
	int z_M = 0;
	/* SOAP date example: 2013-02-19T21:14:25.741-03:00 */
	if ( soap_datetime == NULL ) {
		return 0;
	} 
	if ( soap_datetime[0] == '-' ) {
		return 0;
	}
	if ( strchr(soap_datetime, 'z') || strchr(soap_datetime, 'Z') ) {
		sscanf(soap_datetime, "%d-%d-%dT%d:%d:%d.%d%c",
						  &t.tm_year, &t.tm_mon, &t.tm_mday,
						  &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_usec, &c);
		t.tm_gmtoff = 0;
	} else {
		sscanf(soap_datetime, "%d-%d-%dT%d:%d:%d.%d%c%d:%d",
						  &t.tm_year, &t.tm_mon, &t.tm_mday,
						  &t.tm_hour, &t.tm_min, &t.tm_sec, &t.tm_usec,
						  &z_c, &z_H, &z_M);
		t.tm_gmtoff = ((z_H * 60 + z_M) * 60); // convert H:M to seconds from gmt
		if ( z_c == '-' ) {
			t.tm_gmtoff = -t.tm_gmtoff;
		}
	}
	t.tm_mon --;
	t.tm_year = t.tm_year - 1900;
	t.tm_usec *= 1000;
	apr_time_t apr_time;
	apr_time_exp_gmt_get(&apr_time, &t);
	return apr_time;
}


