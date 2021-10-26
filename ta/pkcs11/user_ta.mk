user-ta-uuid := 7f10a757-4139-4eae-90c9-f2b2eb118139

all: pkcs11-ta-verify-helpers

.PHONY: pkcs11-ta-verify-helpers
pkcs11-ta-verify-helpers:
	@$(cmd-echo-silent) '  CHK    ' $@
	${q}ta/pkcs11/scripts/verify-helpers.sh --quiet
