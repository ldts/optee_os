// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * TPM2 physical transport backend implementing the TCG PC Client Platform
 * TPM Profile (PTP) SPI protocol (a.k.a. SPI TIS). It is built purely on the
 * generic OP-TEE SPI interface (struct spi_chip), so it is independent of any
 * particular SPI controller: it exposes the tpm2_ptp_phy_ops register
 * interface the FIFO/TIS state machine (tpm2_ptp_fifo.c) expects and
 * translates each register access into a CS-held SPI transaction.
 */

#include <assert.h>
#include <drivers/tpm2_chip.h>
#include <drivers/tpm2_ptp_fifo.h>
#include <drivers/tpm2_spi.h>
#include <inttypes.h>
#include <io.h>
#include <kernel/delay.h>
#include <spi.h>
#include <trace.h>
#include <util.h>

/* Max payload of a single SPI TIS transaction, as encoded in the header */
#define TPM2_SPI_MAX_XFER	64

/*
 * The TPM register window lives at 0x00D4_xxxx in the SPI TIS address
 * space. The FIFO layer passes TIS register offsets below 0x10000
 * (locality is encoded in bits [15:12]).
 */
#define TPM2_SPI_TIS_BASE	0x00d40000

/* Header byte 0: read/write direction bit and (len - 1) size field */
#define TPM2_SPI_READ		0x80
#define TPM2_SPI_HDR_LEN	4

/* Wait-state flow control: MISO LSB set means the TPM is ready */
#define TPM2_SPI_WAIT_STATE_RDY	BIT(0)

/* Number of wait-state polling bytes before giving up */
#define TPM2_SPI_WAIT_RETRIES	50

static struct spi_chip *tpm2_spi_ctrl;

static const struct tpm2_ptp_ops tpm2_fifo_ops = {
	.init = tpm2_fifo_init,
	.end = tpm2_fifo_end,
	.send = tpm2_fifo_send,
	.recv = tpm2_fifo_recv,
};

/*
 * Run one SPI TIS transaction for up to TPM2_SPI_MAX_XFER bytes at TIS
 * register offset adr. CS is asserted for the whole header + wait-state +
 * data sequence and deasserted at the end.
 */
static enum tpm2_result tpm2_spi_xfer_one(struct spi_chip *chip, bool read,
					  uint32_t adr, uint16_t len,
					  uint8_t *buf)
{
	uint8_t hdr[TPM2_SPI_HDR_LEN] = { };
	uint8_t rsp[TPM2_SPI_HDR_LEN] = { };
	uint8_t zero[TPM2_SPI_MAX_XFER] = { };
	uint32_t addr = TPM2_SPI_TIS_BASE | (adr & 0xffff);
	enum tpm2_result ret = TPM2_ERR_IO;
	unsigned int retries = 0;
	bool ready = false;

	assert(len >= 1 && len <= TPM2_SPI_MAX_XFER);

	hdr[0] = (read ? TPM2_SPI_READ : 0) | (len - 1);
	hdr[1] = (addr >> 16) & 0xff;
	hdr[2] = (addr >> 8) & 0xff;
	hdr[3] = addr & 0xff;

	DMSG("TPM2 SPI: %s adr=%#" PRIx32 " len=%u", read ? "RD" : "WR", adr,
	     len);

	chip->ops->start(chip);

	/*
	 * TCG PTP SPI (TIS) software flow control: shift the 4-byte header
	 * full-duplex; the MISO byte clocked in during the last header byte is
	 * the first wait-state status. If its ready bit (LSB) is clear, keep
	 * clocking single bytes until the TPM asserts ready, then shift the
	 * payload -- reads capture MISO, writes drive MOSI. CS stays asserted
	 * across the whole sequence (the SPI controller must hold it between
	 * these chained transfers).
	 */
	if (chip->ops->txrx8(chip, hdr, rsp, TPM2_SPI_HDR_LEN) != SPI_OK) {
		EMSG("TPM2 SPI: header transfer failed");
		goto out;
	}

	if (rsp[TPM2_SPI_HDR_LEN - 1] & TPM2_SPI_WAIT_STATE_RDY) {
		ready = true;
	} else {
		for (retries = 0; retries < TPM2_SPI_WAIT_RETRIES; retries++) {
			uint8_t tx = 0;
			uint8_t rx = 0;

			if (chip->ops->txrx8(chip, &tx, &rx, 1) != SPI_OK) {
				EMSG("TPM2 SPI: wait-state transfer failed");
				goto out;
			}

			if (rx & TPM2_SPI_WAIT_STATE_RDY) {
				ready = true;
				break;
			}

			mdelay(TPM2_TIMEOUT_RETRY_MS);
		}
	}

	if (!ready) {
		EMSG("TPM2 SPI: wait-state never asserted after %u polls",
		     TPM2_SPI_WAIT_RETRIES);
		ret = TPM2_ERR_TIMEOUT;
		goto out;
	}

	if (read) {
		if (chip->ops->txrx8(chip, zero, buf, len) != SPI_OK) {
			EMSG("TPM2 SPI: read data transfer failed");
			goto out;
		}
	} else {
		if (chip->ops->txrx8(chip, buf, zero, len) != SPI_OK) {
			EMSG("TPM2 SPI: write data transfer failed");
			goto out;
		}
	}

	ret = TPM2_OK;
out:
	chip->ops->end(chip);

	if (ret)
		EMSG("TPM2 SPI: xfer adr=%#" PRIx32 " failed, ret=%d", adr, ret);

	return ret;
}

/*
 * Byte-stream access at TIS offset adr. The FIFO layer may request bursts
 * larger than a single SPI TIS transaction can carry (e.g. DATA_FIFO
 * reads/writes), so split into <= TPM2_SPI_MAX_XFER chunks. The same
 * register offset is reused for every chunk: the TPM's DATA_FIFO auto-
 * advances internally and status/access registers are single bytes.
 */
static enum tpm2_result tpm2_spi_rw8(struct spi_chip *chip, bool read,
				     uint32_t adr, uint16_t len, uint8_t *buf)
{
	enum tpm2_result ret = TPM2_OK;
	uint16_t done = 0;

	if (!len)
		return TPM2_ERR_INVALID_ARG;

	while (done < len) {
		uint16_t chunk = MIN((uint16_t)(len - done),
				     (uint16_t)TPM2_SPI_MAX_XFER);

		ret = tpm2_spi_xfer_one(chip, read, adr, chunk, buf + done);
		if (ret)
			return ret;

		done += chunk;
	}

	return TPM2_OK;
}

static enum tpm2_result tpm2_spi_rx8(struct tpm2_chip *chip __unused,
				     uint32_t adr, uint16_t len, uint8_t *buf)
{
	return tpm2_spi_rw8(tpm2_spi_ctrl, true, adr, len, buf);
}

static enum tpm2_result tpm2_spi_tx8(struct tpm2_chip *chip __unused,
				     uint32_t adr, uint16_t len, uint8_t *buf)
{
	return tpm2_spi_rw8(tpm2_spi_ctrl, false, adr, len, buf);
}

static enum tpm2_result tpm2_spi_rx32(struct tpm2_chip *chip __unused,
				      uint32_t adr, uint32_t *buf)
{
	uint8_t b[4] = { };
	enum tpm2_result ret = TPM2_OK;

	ret = tpm2_spi_rw8(tpm2_spi_ctrl, true, adr, sizeof(b), b);
	if (ret)
		return ret;

	*buf = get_le32(b);

	return TPM2_OK;
}

static enum tpm2_result tpm2_spi_tx32(struct tpm2_chip *chip __unused,
				      uint32_t adr, uint32_t val)
{
	uint8_t b[4] = { };

	put_le32(b, val);

	return tpm2_spi_rw8(tpm2_spi_ctrl, false, adr, sizeof(b), b);
}

static const struct tpm2_ptp_phy_ops tpm2_spi_ops = {
	.rx32 = tpm2_spi_rx32,
	.tx32 = tpm2_spi_tx32,
	.rx8 = tpm2_spi_rx8,
	.tx8 = tpm2_spi_tx8,
};

static struct tpm2_chip tpm2_spi_chip = {
	.phy_ops = &tpm2_spi_ops,
	.ops = &tpm2_fifo_ops,
};

enum tpm2_result tpm2_spi_init(struct spi_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	uint32_t did_vid = 0;
	uint8_t access = 0;

	assert(chip);
	tpm2_spi_ctrl = chip;

	/*
	 * Read the fixed vendor/device ID before starting the TPM stack: a
	 * sane DID_VID is the definitive "a TPM is responding on this bus"
	 * check (0x00000000 means MISO is dead, 0xffffffff means it floats).
	 */
	ret = tpm2_spi_rx32(&tpm2_spi_chip, TPM2_DID_VID(0), &did_vid);
	if (ret)
		EMSG("TPM2 SPI: DID_VID read failed: %d", ret);
	else
		IMSG("TPM2 SPI: TPM detected, DID_VID=%#" PRIx32, did_vid);

	ret = tpm2_spi_rx8(&tpm2_spi_chip, TPM2_ACCESS(0), sizeof(access),
			   &access);
	if (!ret)
		DMSG("TPM2 SPI: ACCESS=%#"PRIx8" (VALID=%u active=%u)", access,
		     !!(access & TPM2_ACCESS_VALID),
		     !!(access & TPM2_ACCESS_ACTIVE_LOCALITY));

	ret = tpm2_chip_register(&tpm2_spi_chip);
	if (ret) {
		EMSG("TPM2 SPI: chip registration failed: %d", ret);
		return ret;
	}

	DMSG("TPM2 SPI: chip registered");

	return TPM2_OK;
}
