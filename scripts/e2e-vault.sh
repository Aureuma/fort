#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo test fort_e2e_roundtrip_preserves_vault_ciphertext_contract -- --nocapture "$@"
