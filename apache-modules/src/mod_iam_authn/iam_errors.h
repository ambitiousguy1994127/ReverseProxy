/*
 * Apache Module for OpenIAM Authenticaton. Error codes
 * Authors: Evgeniy Sergeev, OpenIAM LLC
 */

#define IAM_ERROR           (APR_OS_START_USERERR + 100)
#define IAM_ESB_ERROR       (APR_OS_START_USERERR + 101)
#define IAM_XML_ERROR       (APR_OS_START_USERERR + 103)
#define IAM_CURL_ERROR      (APR_OS_START_USERERR + 104)
#define IAM_CRYPTO_ERROR    (APR_OS_START_USERERR + 105)
#define IAM_AUTH_ERROR      (APR_OS_START_USERERR + 106)
#define IAM_DB_ERROR        (APR_OS_START_USERERR + 107)
#define IAM_DATA_ERROR      (APR_OS_START_USERERR + 108)
#define IAM_CACHE_EXPIRED   (APR_OS_START_USERERR + 109)
#define IAM_RPROXY_ERROR    (APR_OS_START_USERERR + 110)
#define IAM_DB_FULL         (APR_OS_START_USERERR + 111)
#define IAM_SHM_ERROR       (APR_OS_START_USERERR + 112)
#define IAM_SHM_CACHE_ERROR (APR_OS_START_USERERR + 113)
#define IAM_SHM_NOT_SYNCED  (APR_OS_START_USERERR + 114)
#define IAM_NOT_SSL_CONN    (APR_OS_START_USERERR + 120)
#define IAM_NO_CLIENT_CERT  (APR_OS_START_USERERR + 121)
#define IAM_CLIENT_CERT_ERROR (APR_OS_START_USERERR + 122)
#define IAM_NOMEM_ERROR     (APR_OS_START_USERERR + 123)
#define IAM_JSON_ERROR      (APR_OS_START_USERERR + 124)



#define OPENIAM_ERROR            IAM_ERROR
#define OPENIAM_DATA_ERROR       IAM_DATA_ERROR
#define OPENIAM_DB_ERROR         IAM_DB_ERROR
#define OPENIAM_DB_FULL          IAM_DB_FULL
#define OPENIAM_CACHE_EXPIRED    IAM_CACHE_EXPIRED
#define OPENIAM_RPROXY_ERROR     IAM_RPROXY_ERROR
#define OPENIAM_SHM_ERROR        IAM_SHM_ERROR
#define OPENIAM_SHM_CACHE_ERROR  IAM_SHM_CACHE_ERROR
#define OPENIAM_SHM_NOT_SYNCED   IAM_SHM_NOT_SYNCED
#define OPENIAM_NOT_SSL_CONN     IAM_NOT_SSL_CONN
#define OPENIAM_NO_CLIENT_CERT   IAM_NO_CLIENT_CERT
#define OPENIAM_CLIENT_CERT_ERROR  IAM_CLIENT_CERT_ERROR
#define OPENIAM_NOMEM_ERROR      IAM_NOMEM_ERROR
#define OPENIAM_JSON_ERROR       IAM_JSON_ERROR

#define IAM_REDIRECTED      (APR_OS_START_USERERR + 301)
