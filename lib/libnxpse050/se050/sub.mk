cflags-y += -Wno-error
cflags-y += -Wno-implicit-function-declaration
cflags-y += -Wno-suggest-attribute=format
cflags-y += -Wno-unused-result

cflags-y += -DAX_EMBEDDED=1
cflags-y += -DVERBOSE_APDU_LOGS=0
cflags-y += -DT1oI2C_UM11225
cflags-y += -DT1oI2C
cflags-y += -DSSS_USE_FTR_FILE

incdirs-y += ./glue/include
incdirs-y += ./simw-top/hostlib/hostLib/inc/
incdirs-y += ./simw-top/hostlib/hostLib/libCommon/infra/
incdirs-y += ./simw-top/hostlib/hostLib/libCommon/smCom/
incdirs-y += ./simw-top/hostlib/hostLib/libCommon/smCom/T1oI2C/
incdirs-y += ./simw-top/hostlib/hostLib/platform/inc/
incdirs-y += ./simw-top/hostlib/hostLib/se05x_03_xx_xx/
incdirs-y += ./simw-top/sss/inc/
incdirs-y += ./simw-top/sss/ex/inc/
incdirs-y += ./simw-top/sss/port/default/
incdirs-y += ./simw-top/sss/src/user/crypto/

# glue code
srcs-y += glue/stubs.c
srcs-y += glue/wraps.c
srcs-y += glue/i2c.c
srcs-y += glue/smCom.c

# hostlib/hostLib/libCommon/smCom/
srcs-y += simw-top/hostlib/hostLib/libCommon/smCom/smComT1oI2C.c

# hostlib/hostLib/libCommon/smCom/T1oI2C/
srcs-y += simw-top/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEse_Api.c
srcs-y += simw-top/hostlib/hostLib/libCommon/smCom/T1oI2C/phNxpEseProto7816_3.c

# hostlib/hostLib/libCommon/infra/
srcs-y += simw-top/hostlib/hostLib/libCommon/infra/sm_connect.c
srcs-y += simw-top/hostlib/hostLib/libCommon/infra/sm_apdu.c
srcs-y += simw-top/hostlib/hostLib/libCommon/infra/global_platf.c

# hostlib/hostLib/libCommon/scp/
srcs-y += simw-top/hostlib/hostLib/libCommon/scp/scp.c

# hostlib/hostLib/libCommon/nxScp/
srcs-y += simw-top/hostlib/hostLib/libCommon/nxScp/nxScp03_Com.c

# hostlib/hostLib/se05x_03_xx_xx/
srcs-y += simw-top/hostlib/hostLib/se05x_03_xx_xx/se05x_APDU.c

# hostlib/hostLib/se05x/src
srcs-y += simw-top/hostlib/hostLib/se05x/src/se05x_mw.c
srcs-y += simw-top/hostlib/hostLib/se05x/src/se05x_tlv.c
srcs-y += simw-top/hostlib/hostLib/se05x/src/se05x_ECC_curves.c

# sss/src
srcs-y += simw-top/sss/src/fsl_sss_util_rsa_sign_utils.c
srcs-y += simw-top/sss/src/fsl_sss_util_asn1_der.c

# sss/src/se05x/
srcs-y += simw-top/sss/src/se05x/fsl_sss_se05x_policy.c
srcs-y += simw-top/sss/src/se05x/fsl_sss_se05x_mw.c
srcs-y += simw-top/sss/src/se05x/fsl_sss_se05x_apis.c
srcs-y += simw-top/sss/src/se05x/fsl_sss_se05x_scp03.c

# sss/src/user/
srcs-y += simw-top/sss/src/user/fsl_sss_user_impl.c

# sss/src/user/crypto
srcs-y += simw-top/sss/src/user/crypto/aes.c
srcs-y += simw-top/sss/src/user/crypto/aes_cmac.c
srcs-y += simw-top/sss/src/user/crypto/aes_cmac_multistep.c
