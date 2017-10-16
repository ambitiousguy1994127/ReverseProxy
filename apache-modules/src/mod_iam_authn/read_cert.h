/*
 * OpenIAM Authentication: Read ssl client certificate
 * Authors: OpenIAM Developers
 */
#ifndef __MOD_OPENIAM_READ_CERT_H__
#define __MOD_OPENIAM_READ_CERT_H__

#include <apr.h>
#include <httpd.h>

apr_status_t openiam_read_cert(request_rec* r, char **out_pem);

#endif // __MOD_OPENIAM_READ_CERT_H__
