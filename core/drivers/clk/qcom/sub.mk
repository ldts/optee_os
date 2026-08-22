global-incdirs-y += .
global-incdirs-y += platform/$(PLATFORM_FLAVOR)

srcs-y += clk-qcom.c
srcs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)/clock-qcom-pas.c
srcs-$(CFG_QCOM_CLK_CFG) += platform/$(PLATFORM_FLAVOR)/clk-qcom-cfg.c

# Aggregate CX/MX rail-corner voting behind the set-rate path. RPMh targets
# build the RPMh backend; without it a CLK_CFG build fails to link rather than
# silently running under-volted.
ifeq ($(CFG_QCOM_CLK_CFG),y)
srcs-$(CFG_QCOM_RPMH_CLIENT) += rpmh_rail.c
endif

incdirs-y += .
incdirs-$(CFG_QCOM_PAS_PTA) += platform/$(PLATFORM_FLAVOR)
incdirs-$(CFG_QCOM_CLK_CFG) += platform/$(PLATFORM_FLAVOR)
