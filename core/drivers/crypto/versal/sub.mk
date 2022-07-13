incdirs-y += include

srcs-y += ipi.c
srcs-y += authenc.c
srcs-y += ecc.c
srcs-y += rsa.c
srcs-y += hash.c

srcs-$(CFG_VERSAL_TESTS) += authenc_test.c ecc_test.c hash_test.c rsa_test.c
