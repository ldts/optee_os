global-incdirs-y += .
srcs-y += psci.c
srcs-$(CFG_MX7) += pm-imx7.c psci-suspend-imx7.S imx7_suspend.c \
	cpuidle-imx7d.c psci-cpuidle-imx7.S gpcv2.c
srcs-$(CFG_MX7ULP) += pm-imx7ulp.c psci-suspend-imx7ulp.S imx7ulp_suspend.c
