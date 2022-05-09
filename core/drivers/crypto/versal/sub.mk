incdirs-y += include

cflags-y += -Wno-unused-parameter

srcs-y += ipi.c
srcs-y += ecc.c      ecc_test.c
srcs-y += rsa.c      rsa_test.c
srcs-y += hash.c     hash_test.c
srcs-y += authenc.c  authenc_test.c
