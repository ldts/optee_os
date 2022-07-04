incdirs-y += include

srcs-y += ipi.c
srcs-y += authenc.c
srcs-y += ecc.c
srcs-y += rsa.c

srcs-$(CFG_VERSAL_TESTS) += ecc_test.c rsa_test.c hash_test.c authenc_test.c
