# Enable the crypto driver
$(call force,CFG_CRYPTO_DRIVER,y)
CFG_CRYPTO_DRIVER_DEBUG ?= 0

$(call force,CFG_CRYPTO_DRV_ACIPHER,y,Mandated by CFG_NXP_SE05X_ACIPHER_DRV)
$(call force,CFG_CRYPTO_DRV_ECC,y)


