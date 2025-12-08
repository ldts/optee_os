// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2009-2017, The Linux Foundation. All rights reserved.
 * Copyright (c) 2017-2019, Linaro Ltd.
 */

#include <initcall.h>
#include <qcom,ids.h>
#include <smem.h>
#include <socinfo.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

static struct qcom_socinfo {
	const char *machine;
	const char *family;
	char serial_number[32];
	char revision[32];
} qs;

static struct socinfo *soc_info;

/* Little endian abstractions */
#define cpu_to_le16(x)		(x)
#define cpu_to_le32(x)		(x)
#define cpu_to_le64(x)		(x)
#define le16_to_cpu(x)		(x)
#define le32_to_cpu(x)		(x)
#define le64_to_cpu(x)		(x)

/* Helper macros to create soc_id table */
#define qcom_board_id(_id)					\
	{							\
		.id   = QCOM_ID_##_id,				\
		.name = TO_STR(_id),				\
	}

#define qcom_board_id_named(_id, _name)				\
	{							\
		.id   = QCOM_ID_##_id,				\
		.name = (_name),				\
	}

#define SMEM_IMAGE_VERSION_BLOCKS_COUNT		32
#define SMEM_IMAGE_VERSION_SIZE			4096
#define SMEM_IMAGE_VERSION_NAME_SIZE		75
#define SMEM_IMAGE_VERSION_VARIANT_SIZE		20
#define SMEM_IMAGE_VERSION_OEM_SIZE		32

/*
 * SMEM Image table indices
 */
#define SMEM_IMAGE_TABLE_BOOT_INDEX		0
#define SMEM_IMAGE_TABLE_TZ_INDEX		1
#define SMEM_IMAGE_TABLE_RPM_INDEX		3
#define SMEM_IMAGE_TABLE_APPS_INDEX		10
#define SMEM_IMAGE_TABLE_MPSS_INDEX		11
#define SMEM_IMAGE_TABLE_ADSP_INDEX		12
#define SMEM_IMAGE_TABLE_CNSS_INDEX		13
#define SMEM_IMAGE_TABLE_VIDEO_INDEX		14
#define SMEM_IMAGE_TABLE_DSPS_INDEX		15
#define SMEM_IMAGE_TABLE_CDSP_INDEX		16
#define SMEM_IMAGE_TABLE_CDSP1_INDEX		19
#define SMEM_IMAGE_TABLE_GPDSP_INDEX		20
#define SMEM_IMAGE_TABLE_GPDSP1_INDEX		21
#define SMEM_IMAGE_VERSION_TABLE		469

/*
 * SMEM Image table names
 */
static const char *const socinfo_image_names[] = {
	[SMEM_IMAGE_TABLE_ADSP_INDEX] = "adsp",
	[SMEM_IMAGE_TABLE_APPS_INDEX] = "apps",
	[SMEM_IMAGE_TABLE_BOOT_INDEX] = "boot",
	[SMEM_IMAGE_TABLE_CNSS_INDEX] = "cnss",
	[SMEM_IMAGE_TABLE_MPSS_INDEX] = "mpss",
	[SMEM_IMAGE_TABLE_RPM_INDEX] = "rpm",
	[SMEM_IMAGE_TABLE_TZ_INDEX] = "tz",
	[SMEM_IMAGE_TABLE_VIDEO_INDEX] = "video",
	[SMEM_IMAGE_TABLE_DSPS_INDEX] = "dsps",
	[SMEM_IMAGE_TABLE_CDSP_INDEX] = "cdsp",
	[SMEM_IMAGE_TABLE_CDSP1_INDEX] = "cdsp1",
	[SMEM_IMAGE_TABLE_GPDSP_INDEX] = "gpdsp",
	[SMEM_IMAGE_TABLE_GPDSP1_INDEX] = "gpdsp1",
};

static const char *const pmic_models[] = {
	[0]  = "Unknown PMIC model",
	[1]  = "PM8941",
	[2]  = "PM8841",
	[3]  = "PM8019",
	[4]  = "PM8226",
	[5]  = "PM8110",
	[6]  = "PMA8084",
	[7]  = "PMI8962",
	[8]  = "PMD9635",
	[9]  = "PM8994",
	[10] = "PMI8994",
	[11] = "PM8916",
	[12] = "PM8004",
	[13] = "PM8909/PM8058",
	[14] = "PM8028",
	[15] = "PM8901",
	[16] = "PM8950/PM8027",
	[17] = "PMI8950/ISL9519",
	[18] = "PMK8001/PM8921",
	[19] = "PMI8996/PM8018",
	[20] = "PM8998/PM8015",
	[21] = "PMI8998/PM8014",
	[22] = "PM8821",
	[23] = "PM8038",
	[24] = "PM8005/PM8922",
	[25] = "PM8917/PM8937",
	[26] = "PM660L",
	[27] = "PM660",
	[30] = "PM8150",
	[31] = "PM8150L",
	[32] = "PM8150B",
	[33] = "PMK8002",
	[36] = "PM8009",
	[37] = "PMI632",
	[38] = "PM8150C",
	[40] = "PM6150",
	[41] = "SMB2351",
	[44] = "PM8008",
	[45] = "PM6125",
	[46] = "PM7250B",
	[47] = "PMK8350",
	[48] = "PM8350",
	[49] = "PM8350C",
	[50] = "PM8350B",
	[51] = "PMR735A",
	[52] = "PMR735B",
	[54] = "PM6350",
	[55] = "PM4125",
	[58] = "PM8450",
	[65] = "PM8010",
	[69] = "PM8550VS",
	[70] = "PM8550VE",
	[71] = "PM8550B",
	[72] = "PMR735D",
	[73] = "PM8550",
	[74] = "PMK8550",
	[82] = "PMC8380",
	[83] = "SMB2360",
};

struct smem_image_version {
	char name[SMEM_IMAGE_VERSION_NAME_SIZE];
	char variant[SMEM_IMAGE_VERSION_VARIANT_SIZE];
	char pad;
	char oem[SMEM_IMAGE_VERSION_OEM_SIZE];
};

struct soc_id {
	unsigned int id;
	const char *name;
};

static const struct soc_id soc_id[] = {
	qcom_board_id(MSM8260),
	qcom_board_id(MSM8660),
	qcom_board_id(APQ8060),
	qcom_board_id(MSM8960),
	qcom_board_id(APQ8064),
	qcom_board_id(MSM8930),
	qcom_board_id(MSM8630),
	qcom_board_id(MSM8230),
	qcom_board_id(APQ8030),
	qcom_board_id(MSM8627),
	qcom_board_id(MSM8227),
	qcom_board_id(MSM8660A),
	qcom_board_id(MSM8260A),
	qcom_board_id(APQ8060A),
	qcom_board_id(MSM8974),
	qcom_board_id(MSM8225),
	qcom_board_id(MSM8625),
	qcom_board_id(MPQ8064),
	qcom_board_id(MSM8960AB),
	qcom_board_id(APQ8060AB),
	qcom_board_id(MSM8260AB),
	qcom_board_id(MSM8660AB),
	qcom_board_id(MSM8930AA),
	qcom_board_id(MSM8630AA),
	qcom_board_id(MSM8230AA),
	qcom_board_id(MSM8626),
	qcom_board_id(MSM8610),
	qcom_board_id(APQ8064AB),
	qcom_board_id(MSM8930AB),
	qcom_board_id(MSM8630AB),
	qcom_board_id(MSM8230AB),
	qcom_board_id(APQ8030AB),
	qcom_board_id(MSM8226),
	qcom_board_id(MSM8526),
	qcom_board_id(APQ8030AA),
	qcom_board_id(MSM8110),
	qcom_board_id(MSM8210),
	qcom_board_id(MSM8810),
	qcom_board_id(MSM8212),
	qcom_board_id(MSM8612),
	qcom_board_id(MSM8112),
	qcom_board_id(MSM8125),
	qcom_board_id(MSM8225Q),
	qcom_board_id(MSM8625Q),
	qcom_board_id(MSM8125Q),
	qcom_board_id(APQ8064AA),
	qcom_board_id(APQ8084),
	qcom_board_id(MSM8130),
	qcom_board_id(MSM8130AA),
	qcom_board_id(MSM8130AB),
	qcom_board_id(MSM8627AA),
	qcom_board_id(MSM8227AA),
	qcom_board_id(APQ8074),
	qcom_board_id(MSM8274),
	qcom_board_id(MSM8674),
	qcom_board_id(MDM9635),
	qcom_board_id_named(MSM8974PRO_AC, "MSM8974PRO-AC"),
	qcom_board_id(MSM8126),
	qcom_board_id(APQ8026),
	qcom_board_id(MSM8926),
	qcom_board_id(IPQ8062),
	qcom_board_id(IPQ8064),
	qcom_board_id(IPQ8066),
	qcom_board_id(IPQ8068),
	qcom_board_id(MSM8326),
	qcom_board_id(MSM8916),
	qcom_board_id(MSM8994),
	qcom_board_id_named(APQ8074PRO_AA, "APQ8074PRO-AA"),
	qcom_board_id_named(APQ8074PRO_AB, "APQ8074PRO-AB"),
	qcom_board_id_named(APQ8074PRO_AC, "APQ8074PRO-AC"),
	qcom_board_id_named(MSM8274PRO_AA, "MSM8274PRO-AA"),
	qcom_board_id_named(MSM8274PRO_AB, "MSM8274PRO-AB"),
	qcom_board_id_named(MSM8274PRO_AC, "MSM8274PRO-AC"),
	qcom_board_id_named(MSM8674PRO_AA, "MSM8674PRO-AA"),
	qcom_board_id_named(MSM8674PRO_AB, "MSM8674PRO-AB"),
	qcom_board_id_named(MSM8674PRO_AC, "MSM8674PRO-AC"),
	qcom_board_id_named(MSM8974PRO_AA, "MSM8974PRO-AA"),
	qcom_board_id_named(MSM8974PRO_AB, "MSM8974PRO-AB"),
	qcom_board_id(APQ8028),
	qcom_board_id(MSM8128),
	qcom_board_id(MSM8228),
	qcom_board_id(MSM8528),
	qcom_board_id(MSM8628),
	qcom_board_id(MSM8928),
	qcom_board_id(MSM8510),
	qcom_board_id(MSM8512),
	qcom_board_id(MSM8936),
	qcom_board_id(MDM9640),
	qcom_board_id(MSM8939),
	qcom_board_id(APQ8036),
	qcom_board_id(APQ8039),
	qcom_board_id(MSM8236),
	qcom_board_id(MSM8636),
	qcom_board_id(MSM8909),
	qcom_board_id(MSM8996),
	qcom_board_id(APQ8016),
	qcom_board_id(MSM8216),
	qcom_board_id(MSM8116),
	qcom_board_id(MSM8616),
	qcom_board_id(MSM8992),
	qcom_board_id(APQ8092),
	qcom_board_id(APQ8094),
	qcom_board_id(MSM8209),
	qcom_board_id(MSM8208),
	qcom_board_id(MDM9209),
	qcom_board_id(MDM9309),
	qcom_board_id(MDM9609),
	qcom_board_id(MSM8239),
	qcom_board_id(MSM8952),
	qcom_board_id(APQ8009),
	qcom_board_id(MSM8956),
	qcom_board_id(MSM8929),
	qcom_board_id(MSM8629),
	qcom_board_id(MSM8229),
	qcom_board_id(APQ8029),
	qcom_board_id(APQ8056),
	qcom_board_id(MSM8609),
	qcom_board_id(APQ8076),
	qcom_board_id(MSM8976),
	qcom_board_id(IPQ8065),
	qcom_board_id(IPQ8069),
	qcom_board_id(MDM9650),
	qcom_board_id(MDM9655),
	qcom_board_id(MDM9250),
	qcom_board_id(MDM9255),
	qcom_board_id(MDM9350),
	qcom_board_id(APQ8052),
	qcom_board_id(MDM9607),
	qcom_board_id(APQ8096),
	qcom_board_id(MSM8998),
	qcom_board_id(MSM8953),
	qcom_board_id(MSM8937),
	qcom_board_id(APQ8037),
	qcom_board_id(MDM8207),
	qcom_board_id(MDM9207),
	qcom_board_id(MDM9307),
	qcom_board_id(MDM9628),
	qcom_board_id(MSM8909W),
	qcom_board_id(APQ8009W),
	qcom_board_id(MSM8996L),
	qcom_board_id(MSM8917),
	qcom_board_id(APQ8053),
	qcom_board_id(MSM8996SG),
	qcom_board_id(APQ8017),
	qcom_board_id(MSM8217),
	qcom_board_id(MSM8617),
	qcom_board_id(MSM8996AU),
	qcom_board_id(APQ8096AU),
	qcom_board_id(APQ8096SG),
	qcom_board_id(MSM8940),
	qcom_board_id(SDX201),
	qcom_board_id(SDM660),
	qcom_board_id(SDM630),
	qcom_board_id(APQ8098),
	qcom_board_id(MSM8920),
	qcom_board_id(SDM845),
	qcom_board_id(MDM9206),
	qcom_board_id(IPQ8074),
	qcom_board_id(SDA660),
	qcom_board_id(SDM658),
	qcom_board_id(SDA658),
	qcom_board_id(SDA630),
	qcom_board_id(MSM8905),
	qcom_board_id(SDX202),
	qcom_board_id(SDM670),
	qcom_board_id(SDM450),
	qcom_board_id(SM8150),
	qcom_board_id(SDA845),
	qcom_board_id(IPQ8072),
	qcom_board_id(IPQ8076),
	qcom_board_id(IPQ8078),
	qcom_board_id(SDM636),
	qcom_board_id(SDA636),
	qcom_board_id(SDM632),
	qcom_board_id(SDA632),
	qcom_board_id(SDA450),
	qcom_board_id(SDM439),
	qcom_board_id(SDM429),
	qcom_board_id(SM8250),
	qcom_board_id(SA8155),
	qcom_board_id(SDA439),
	qcom_board_id(SDA429),
	qcom_board_id(SM7150),
	qcom_board_id(SM7150P),
	qcom_board_id(IPQ8070),
	qcom_board_id(IPQ8071),
	qcom_board_id(QM215),
	qcom_board_id(IPQ8072A),
	qcom_board_id(IPQ8074A),
	qcom_board_id(IPQ8076A),
	qcom_board_id(IPQ8078A),
	qcom_board_id(SM6125),
	qcom_board_id(IPQ8070A),
	qcom_board_id(IPQ8071A),
	qcom_board_id(IPQ8172),
	qcom_board_id(IPQ8173),
	qcom_board_id(IPQ8174),
	qcom_board_id(IPQ6018),
	qcom_board_id(IPQ6028),
	qcom_board_id(SDM429W),
	qcom_board_id(SM4250),
	qcom_board_id(IPQ6000),
	qcom_board_id(IPQ6010),
	qcom_board_id(SC7180),
	qcom_board_id(SM6350),
	qcom_board_id(QCM2150),
	qcom_board_id(SDA429W),
	qcom_board_id(SM8350),
	qcom_board_id(QCM2290),
	qcom_board_id(SM7125),
	qcom_board_id(SM6115),
	qcom_board_id(IPQ5010),
	qcom_board_id(IPQ5018),
	qcom_board_id(IPQ5028),
	qcom_board_id(SC8280XP),
	qcom_board_id(IPQ6005),
	qcom_board_id(QRB5165),
	qcom_board_id(SM8450),
	qcom_board_id(SM7225),
	qcom_board_id(SA8295P),
	qcom_board_id(SA8540P),
	qcom_board_id(QCM4290),
	qcom_board_id(QCS4290),
	qcom_board_id(SM7325),
	qcom_board_id_named(SM8450_2, "SM8450"),
	qcom_board_id_named(SM8450_3, "SM8450"),
	qcom_board_id(SC7280),
	qcom_board_id(SC7180P),
	qcom_board_id(QCM6490),
	qcom_board_id(SM7325P),
	qcom_board_id(IPQ5000),
	qcom_board_id(IPQ0509),
	qcom_board_id(IPQ0518),
	qcom_board_id(SM6375),
	qcom_board_id(IPQ9514),
	qcom_board_id(IPQ9550),
	qcom_board_id(IPQ9554),
	qcom_board_id(IPQ9570),
	qcom_board_id(IPQ9574),
	qcom_board_id(SM8550),
	qcom_board_id(IPQ5016),
	qcom_board_id(IPQ9510),
	qcom_board_id(QRB4210),
	qcom_board_id(QRB2210),
	qcom_board_id(SAR2130P),
	qcom_board_id(SM8475),
	qcom_board_id(SM8475P),
	qcom_board_id(SA8255P),
	qcom_board_id(SA8775P),
	qcom_board_id(QRU1000),
	qcom_board_id(SM8475_2),
	qcom_board_id(QDU1000),
	qcom_board_id(X1E80100),
	qcom_board_id(SM8650),
	qcom_board_id(SM4450),
	qcom_board_id(SAR1130P),
	qcom_board_id(QDU1010),
	qcom_board_id(QRU1032),
	qcom_board_id(QRU1052),
	qcom_board_id(QRU1062),
	qcom_board_id(IPQ5332),
	qcom_board_id(IPQ5322),
	qcom_board_id(IPQ5312),
	qcom_board_id(IPQ5302),
	qcom_board_id(QCS8550),
	qcom_board_id(QCM8550),
	qcom_board_id(SM8750),
	qcom_board_id(IPQ5300),
	qcom_board_id(IPQ5321),
	qcom_board_id(IPQ5424),
	qcom_board_id(IPQ5404),
	qcom_board_id(QCS9100),
	qcom_board_id(QCS8300),
	qcom_board_id(QCS8275),
	qcom_board_id(QCS9075),
	qcom_board_id(QCS615),
};

static const char *socinfo_machine(uint32_t id)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(soc_id); idx++) {
		if (soc_id[idx].id == id)
			return soc_id[idx].name;
	}

	return NULL;
}

static void qcom_show_pmic_model(void)
{
	int model = SOCINFO_MINOR(le32_to_cpu(soc_info->pmic_model));

	if (model < 0)
		return;

	if ((uint32_t)model < ARRAY_SIZE(pmic_models) && pmic_models[model])
		IMSG("PMIC: %s\n", pmic_models[model]);
}

static void qcom_show_boot_image(void)
{
	struct smem_image_version *versions = NULL;
	size_t item_size = 0;

	versions = qcom_smem_get(QCOM_SMEM_HOST_ANY,
				 SMEM_IMAGE_VERSION_TABLE,
				 &item_size);
	if (!versions)
		return;

	for (size_t i = 0; i < ARRAY_SIZE(socinfo_image_names); i++) {
		if (!socinfo_image_names[i] ||
		    strncmp(socinfo_image_names[i], "boot", 4))
			continue;

		IMSG("Boot Image: name %s, variant %s, oem %s",
		     versions[i].name, versions[i].variant, versions[i].oem);
	}
}

void qcom_socinfo_show_info(void)
{
	qcom_show_boot_image();
	IMSG("Serial Number: 0x%s", qs.serial_number);
	IMSG("Machine: %d, Rev: %d.%d %s",
	     soc_info->id, qs.revision[0], qs.revision[1],
	     qs.machine ? qs.machine : "");
	qcom_show_pmic_model();
}

static TEE_Result qcom_socinfo_init(void)
{
	size_t item_size = 0;

	soc_info = qcom_smem_get(QCOM_SMEM_HOST_ANY, SMEM_HW_SW_BUILD_ID,
				 &item_size);
	if (!soc_info) {
		DMSG("Socinfo not present");
		return TEE_SUCCESS;
	}

	qs.family = "Snapdragon";
	qs.machine = socinfo_machine(le32_to_cpu(soc_info->id));

	snprintf(qs.revision, sizeof(qs.revision), "%u.%u",
		 SOCINFO_MAJOR(le32_to_cpu(soc_info->ver)),
		 SOCINFO_MINOR(le32_to_cpu(soc_info->ver)));

	if (offsetof(struct socinfo, serial_num) <= item_size)
		snprintf(qs.serial_number, sizeof(qs.serial_number), "%08x",
			 soc_info->serial_num);

	return TEE_SUCCESS;
}

early_init_late(qcom_socinfo_init);
