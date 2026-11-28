#!/bin/sh
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 sigmacatch contributors
#
# Sign a locally built sigmacatch with the Endpoint Security entitlement.
#
#   collector/macos/sign.sh [BINARY]
#
# BINARY defaults to target/release/sigmacatch. By default the signature is
# ad-hoc (`codesign -s -`); set SIGN_IDENTITY to a keychain identity name (for
# example a self-signed "sigmacatch-dev" certificate) when the ad-hoc signature
# is refused with ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
#
#   SIGN_IDENTITY=sigmacatch-dev collector/macos/sign.sh
#
# After signing, the binary must still be run as root; the first connection
# makes macOS prompt for approval (System Settings > Privacy & Security).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=${1:-target/release/sigmacatch}
plist="$here/endpoint-security.entitlements"
identity=${SIGN_IDENTITY:--}

if [ ! -f "$binary" ]; then
    echo "sign.sh: $binary not found — build it first:" >&2
    echo "  cargo build --release --no-default-features --features macos -p sigmacatch" >&2
    exit 1
fi

codesign --force --timestamp=none --sign "$identity" \
    --entitlements "$plist" "$binary"

echo "signed $binary with $plist (identity: $identity)"
codesign --display --entitlements - "$binary" 2>&1
