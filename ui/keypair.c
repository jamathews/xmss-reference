#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../params.h"
#include "../xmss.h"

#ifdef XMSSMT
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_KEYPAIR xmssmt_keypair
#else
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_KEYPAIR xmss_keypair
#endif

int main(int argc, char **argv)
{
    xmss_params params;
    uint32_t oid = 0;
    int parse_oid_result = 0;

    if (argc != 4) {
        fprintf(stderr, "Expected 3 parameters: xmss parameter string (e.g. 'XMSS-SHA2_10_256'), public_key_file, secret_key_file.\n"
                        "Example:\n\n"
                        "xmss_keypair XMSS-SHA2_10_256 public_key.dat secret_key.dat\n\n");
        return -1;
    }

    XMSS_STR_TO_OID(&oid, argv[1]);
    parse_oid_result = XMSS_PARSE_OID(&params, oid);
    if (parse_oid_result != 0) {
        fprintf(stderr, "Error parsing oid.\n");
        return parse_oid_result;
    }

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];

    XMSS_KEYPAIR(pk, sk, oid);

    FILE *pk_file = fopen(argv[2], "wb");
    FILE *sk_file = fopen(argv[3], "wb");

    fwrite(pk, 1, XMSS_OID_LEN + params.pk_bytes, pk_file);
    fwrite(sk, 1, XMSS_OID_LEN + params.sk_bytes, sk_file);

    fclose(stdout);
    fclose(pk_file);
    fclose(sk_file);

    return 0;
}
