#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: scripts/build-guard.sh <command> [args...]" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

FORT_BUILD_JOBS="${FORT_BUILD_JOBS:-2}"
FORT_BUILD_NICE="${FORT_BUILD_NICE:-10}"
FORT_BUILD_LOCK_PATH="${FORT_BUILD_LOCK_PATH:-$repo_root/.artifacts/build.lock}"

mkdir -p "$(dirname -- "$FORT_BUILD_LOCK_PATH")"
: > "$FORT_BUILD_LOCK_PATH"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$FORT_BUILD_JOBS}"
export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-$FORT_BUILD_JOBS}"
export MAKEFLAGS="${MAKEFLAGS:--j$FORT_BUILD_JOBS}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-$FORT_BUILD_JOBS}"
export NINJAFLAGS="${NINJAFLAGS:--j$FORT_BUILD_JOBS}"
export NUMEXPR_NUM_THREADS="${NUMEXPR_NUM_THREADS:-$FORT_BUILD_JOBS}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-$FORT_BUILD_JOBS}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$FORT_BUILD_JOBS}"
export UV_CONCURRENT_BUILDS="${UV_CONCURRENT_BUILDS:-$FORT_BUILD_JOBS}"
export VECLIB_MAXIMUM_THREADS="${VECLIB_MAXIMUM_THREADS:-$FORT_BUILD_JOBS}"

if [ "${FORT_BUILD_GUARD_ACTIVE:-0}" = "1" ]; then
    exec nice -n "$FORT_BUILD_NICE" "$@"
fi

export FORT_BUILD_GUARD_ACTIVE=1

if command -v flock >/dev/null 2>&1; then
    exec nice -n "$FORT_BUILD_NICE" flock "$FORT_BUILD_LOCK_PATH" "$@"
fi

echo "scripts/build-guard.sh requires flock to serialize build commands" >&2
exit 127
