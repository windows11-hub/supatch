#!/bin/bash
# build.sh - build kpm_host for a 5.10 GKI kernel (android-5.10) from 5.10/ dir.
# KDIR must point at a 5.10 kernel tree prepared with CONFIG_CFI_CLANG=y.
# Run inside WSL (root):  bash 5.10/build.sh
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="$HERE/kpm_host-gki-5.10.ko"
KDIR="${KDIR:-/root/kernel_common}"

echo "[*] ensure config has CFI (cfg_cfi.sh must have been run)"
grep -qx 'CONFIG_CFI_CLANG=y' "$KDIR/.config" \
  || { echo "FATAL: CONFIG_CFI_CLANG missing in $KDIR/.config"; exit 1; }

B=/root/prebuilt_clang/clang-r416183/bin
export PATH="$B:$PATH"
TVARS=(ARCH=arm64 LLVM=1 LLVM_IAS=1 CC="$B/clang" HOSTCC=gcc \
       NM="$B/llvm-nm" AR="$B/llvm-ar" LD="$B/ld.lld" \
       OBJCOPY="$B/llvm-objcopy" CROSS_COMPILE=aarch64-linux-gnu-)

echo "[*] syncconfig"
make -C "$KDIR" "${TVARS[@]}" syncconfig >/tmp/sync510.log 2>&1 \
  || { echo "FATAL syncconfig:"; tail -5 /tmp/sync510.log; exit 1; }
grep -qx 'CONFIG_CFI_CLANG=y' "$KDIR/include/config/auto.conf" || echo "WARN: auto.conf CFI missing"

echo "[*] build"
make -C "$KDIR" "${TVARS[@]}" \
  KCFLAGS="-fsanitize-cfi-canonical-jump-tables -ffixed-x18" \
  M="$HERE/../src" modules

echo "[*] verify config still CFI"
grep -E '^CONFIG_(CFI|LTO)' "$KDIR/.config" | grep -v '^#'

echo "[*] verify slowpath symbols compiled in"
readelf -Ws "$HERE/kpm_host.ko" | grep -iE 'cfi|slowpath' | head

cp -f "$HERE/kpm_host.ko" "$TARGET"
echo "=== done: $TARGET ==="
modinfo -F vermagic "$TARGET"
ls -l "$TARGET"
