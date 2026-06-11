#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: scripts/build-guard.sh <command> [args...]" >&2
    exit 64
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

SI_BUILD_JOBS="${SI_BUILD_JOBS:-2}"
SI_BUILD_NICE="${SI_BUILD_NICE:-10}"
SI_BUILD_LOCK_PATH="${SI_BUILD_LOCK_PATH:-$repo_root/.artifacts/build.lock}"

mkdir -p "$(dirname -- "$SI_BUILD_LOCK_PATH")"
: > "$SI_BUILD_LOCK_PATH"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$SI_BUILD_JOBS}"
export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-$SI_BUILD_JOBS}"
export MAKEFLAGS="${MAKEFLAGS:--j$SI_BUILD_JOBS}"
export MKL_NUM_THREADS="${MKL_NUM_THREADS:-$SI_BUILD_JOBS}"
export NINJAFLAGS="${NINJAFLAGS:--j$SI_BUILD_JOBS}"
export NUMEXPR_NUM_THREADS="${NUMEXPR_NUM_THREADS:-$SI_BUILD_JOBS}"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-$SI_BUILD_JOBS}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-$SI_BUILD_JOBS}"
export UV_CONCURRENT_BUILDS="${UV_CONCURRENT_BUILDS:-$SI_BUILD_JOBS}"
export VECLIB_MAXIMUM_THREADS="${VECLIB_MAXIMUM_THREADS:-$SI_BUILD_JOBS}"

if [ "${SI_BUILD_GUARD_ACTIVE:-0}" = "1" ]; then
    exec nice -n "$SI_BUILD_NICE" "$@"
fi

export SI_BUILD_GUARD_ACTIVE=1

if command -v flock >/dev/null 2>&1; then
    exec nice -n "$SI_BUILD_NICE" flock "$SI_BUILD_LOCK_PATH" "$@"
fi

echo "scripts/build-guard.sh requires flock to serialize build commands" >&2
exit 127
