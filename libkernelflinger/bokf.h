#ifndef _BOKF_H_
#define _BOKF_H_
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/conf.h>
typedef struct BOKF_st {
	X509 *cert;
	ASN1_OCTET_STRING *data;
    ASN1_OCTET_STRING *enc_digest;
}BOKF;
DECLARE_ASN1_FUNCTIONS(BOKF)

ASN1_SEQUENCE(BOKF) = {
ASN1_SIMPLE(BOKF, cert, X509),
ASN1_SIMPLE(BOKF, data, ASN1_OCTET_STRING),
ASN1_SIMPLE(BOKF, enc_digest, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(BOKF)
IMPLEMENT_ASN1_FUNCTIONS(BOKF)
#endif