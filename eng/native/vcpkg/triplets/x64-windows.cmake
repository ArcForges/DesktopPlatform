# SPDX-License-Identifier: AGPL-3.0-only
# Keep the pinned standard triplet semantics; select the reviewed compiler runtime relationship.
include("${VCPKG_ROOT_DIR}/triplets/x64-windows.cmake")
set(VCPKG_PLATFORM_TOOLSET_VERSION "14.51.36231")
list(APPEND VCPKG_HASH_ADDITIONAL_FILES "${VCPKG_ROOT_DIR}/triplets/x64-windows.cmake")
