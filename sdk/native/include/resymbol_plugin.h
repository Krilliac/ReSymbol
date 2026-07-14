#ifndef RESYMBOL_PLUGIN_H
#define RESYMBOL_PLUGIN_H

/*
 * ReSymbol native plugin ABI, version 1.
 *
 * This header intentionally exposes only fixed-width values, opaque contexts,
 * borrowed byte/string views, and function pointers. It is valid C11 and C++11.
 * Native plugins are loaded in a dedicated plugin-host process by default. A
 * plugin cannot grant itself in-process execution; that is an explicit host and
 * user trust decision.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#define RESYMBOL_PLUGIN_EXTERN_C extern "C"
#define RESYMBOL_PLUGIN_NOEXCEPT noexcept
#else
#define RESYMBOL_PLUGIN_EXTERN_C extern
#define RESYMBOL_PLUGIN_NOEXCEPT
#endif

#if defined(_WIN32)
#define RESYMBOL_PLUGIN_CALL __cdecl
#if defined(RESYMBOL_PLUGIN_BUILD)
#define RESYMBOL_PLUGIN_VISIBILITY __declspec(dllexport)
#else
#define RESYMBOL_PLUGIN_VISIBILITY
#endif
#elif defined(__GNUC__) || defined(__clang__)
#define RESYMBOL_PLUGIN_CALL
#if defined(RESYMBOL_PLUGIN_BUILD)
#define RESYMBOL_PLUGIN_VISIBILITY __attribute__((visibility("default")))
#else
#define RESYMBOL_PLUGIN_VISIBILITY
#endif
#else
#define RESYMBOL_PLUGIN_CALL
#define RESYMBOL_PLUGIN_VISIBILITY
#endif

#define RESYMBOL_PLUGIN_EXPORT \
    RESYMBOL_PLUGIN_EXTERN_C RESYMBOL_PLUGIN_VISIBILITY

#define RESYMBOL_PLUGIN_ABI_VERSION_MAJOR 1u
#define RESYMBOL_PLUGIN_ABI_VERSION_MINOR 0u
#define RESYMBOL_PLUGIN_ABI_VERSION \
    ((RESYMBOL_PLUGIN_ABI_VERSION_MAJOR << 16u) | \
     RESYMBOL_PLUGIN_ABI_VERSION_MINOR)

/* SemVer contract used by the `api` requirement in plugin.toml. */
#define RESYMBOL_PLUGIN_CONTRACT_VERSION "0.1.0"

#define RESYMBOL_PLUGIN_ENTRYPOINT_NAME "resymbol_plugin_get_api"

typedef int32_t resymbol_status;

#define RESYMBOL_STATUS_OK ((resymbol_status)0)
#define RESYMBOL_STATUS_INVALID_ARGUMENT ((resymbol_status)1)
#define RESYMBOL_STATUS_INCOMPATIBLE_ABI ((resymbol_status)2)
#define RESYMBOL_STATUS_INTERNAL_ERROR ((resymbol_status)3)
#define RESYMBOL_STATUS_UNAVAILABLE ((resymbol_status)4)
#define RESYMBOL_STATUS_PERMISSION_DENIED ((resymbol_status)5)
#define RESYMBOL_STATUS_CANCELLED ((resymbol_status)6)
#define RESYMBOL_STATUS_RESOURCE_LIMIT ((resymbol_status)7)

typedef uint32_t resymbol_log_level;

#define RESYMBOL_LOG_TRACE ((resymbol_log_level)0u)
#define RESYMBOL_LOG_DEBUG ((resymbol_log_level)1u)
#define RESYMBOL_LOG_INFO ((resymbol_log_level)2u)
#define RESYMBOL_LOG_WARN ((resymbol_log_level)3u)
#define RESYMBOL_LOG_ERROR ((resymbol_log_level)4u)

typedef uint32_t resymbol_isolation_requirement;

/* Required for untrusted native plugins and the default for every manifest. */
#define RESYMBOL_ISOLATION_OUT_OF_PROCESS \
    ((resymbol_isolation_requirement)1u)

/*
 * The plugin is technically capable of in-process execution. The host must
 * still keep it out of process unless the user explicitly marks it trusted.
 */
#define RESYMBOL_ISOLATION_TRUSTED_IN_PROCESS_ALLOWED \
    ((resymbol_isolation_requirement)2u)

typedef struct resymbol_string_view {
    const char *data;
    uint64_t length;
} resymbol_string_view;

typedef struct resymbol_byte_view {
    const uint8_t *data;
    uint64_t length;
} resymbol_byte_view;

typedef struct resymbol_mut_byte_span {
    uint8_t *data;
    uint64_t length;
} resymbol_mut_byte_span;

/* All views passed to callbacks are borrowed and valid only for that call. */
typedef void(RESYMBOL_PLUGIN_CALL *resymbol_host_log_fn)(
    void *host_context,
    resymbol_log_level level,
    resymbol_string_view message);

/*
 * Reads an RVA from the binary currently being analyzed. The plugin receives
 * no file handle unless the manifest has separately requested and been granted
 * filesystem access. bytes_read may be smaller than destination.length.
 */
typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_host_read_binary_fn)(
    void *host_context,
    uint64_t rva,
    resymbol_mut_byte_span destination,
    uint64_t *bytes_read);

/*
 * Submits one UTF-8 JSON claim envelope. Plugins propose evidence-backed
 * claims; only the ReSymbol core validates and commits canonical symbol state.
 */
typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_host_submit_claim_fn)(
    void *host_context,
    resymbol_byte_view claim_json_utf8);

typedef uint32_t(RESYMBOL_PLUGIN_CALL *resymbol_host_is_cancelled_fn)(
    void *host_context);

typedef struct resymbol_host_api_v1 {
    /*
     * Set to sizeof(resymbol_host_api_v1). The table and its callbacks remain
     * valid until plugin_api->destroy returns.
     */
    uint32_t struct_size;
    uint32_t abi_version;
    void *host_context;

    resymbol_host_log_fn log;
    resymbol_host_read_binary_fn read_binary;
    resymbol_host_submit_claim_fn submit_claim;
    resymbol_host_is_cancelled_fn is_cancelled;

    /* Must be null. Reserved for append-only ABI evolution. */
    void *reserved[8];
} resymbol_host_api_v1;

typedef struct resymbol_plugin_descriptor_v1 {
    /* Set to sizeof(resymbol_plugin_descriptor_v1). */
    uint32_t struct_size;
    uint32_t abi_version;

    /* These plugin-owned views remain valid until destroy returns. */
    resymbol_string_view id;
    resymbol_string_view name;
    resymbol_string_view version;

    resymbol_isolation_requirement isolation;

    /* UTF-8 JSON arrays matching the manifest capability/permission names. */
    resymbol_byte_view capabilities_json_utf8;
    resymbol_byte_view requested_permissions_json_utf8;

    /* Must be null. Reserved for append-only ABI evolution. */
    void *reserved[8];
} resymbol_plugin_descriptor_v1;

typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_plugin_get_descriptor_fn)(
    void *plugin_context,
    resymbol_plugin_descriptor_v1 *descriptor);

/* init_json_utf8 contains session identity, granted permissions, and limits. */
typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_plugin_initialize_fn)(
    void *plugin_context,
    resymbol_byte_view init_json_utf8);

/*
 * request_json_utf8 is a versioned analysis request. Results are emitted only
 * through host->submit_claim so ownership never crosses the ABI boundary.
 */
typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_plugin_analyze_fn)(
    void *plugin_context,
    resymbol_byte_view request_json_utf8);

typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_plugin_health_check_fn)(
    void *plugin_context);

typedef void(RESYMBOL_PLUGIN_CALL *resymbol_plugin_shutdown_fn)(
    void *plugin_context);

typedef void(RESYMBOL_PLUGIN_CALL *resymbol_plugin_destroy_fn)(
    void *plugin_context);

typedef struct resymbol_plugin_api_v1 {
    /*
     * The host zero-initializes this structure and sets struct_size before
     * calling the entrypoint. The plugin fills only fields that fit.
     */
    uint32_t struct_size;
    uint32_t abi_version;
    void *plugin_context;

    resymbol_plugin_get_descriptor_fn get_descriptor;
    resymbol_plugin_initialize_fn initialize;
    resymbol_plugin_analyze_fn analyze;
    resymbol_plugin_health_check_fn health_check;
    resymbol_plugin_shutdown_fn shutdown;
    resymbol_plugin_destroy_fn destroy;

    /* Must be null. Reserved for append-only ABI evolution. */
    void *reserved[8];
} resymbol_plugin_api_v1;

/*
 * The host serializes lifecycle calls for one plugin_context. A plugin may use
 * worker threads internally, but it must join them before shutdown returns and
 * must not call host callbacks after destroy begins.
 */

typedef resymbol_status(RESYMBOL_PLUGIN_CALL *resymbol_plugin_get_api_fn)(
    uint32_t requested_abi_version,
    const resymbol_host_api_v1 *host_api,
    resymbol_plugin_api_v1 *plugin_api);

/*
 * Every native plugin exports exactly this symbol. The binary ABI version is
 * independent from the manifest contract SemVer above. The host rejects
 * different ABI major versions. Minor revisions are append-only and negotiated
 * with struct_size, so neither side may read beyond the size supplied by the
 * other.
 */
RESYMBOL_PLUGIN_EXPORT resymbol_status RESYMBOL_PLUGIN_CALL
resymbol_plugin_get_api(
    uint32_t requested_abi_version,
    const resymbol_host_api_v1 *host_api,
    resymbol_plugin_api_v1 *plugin_api) RESYMBOL_PLUGIN_NOEXCEPT;

#endif /* RESYMBOL_PLUGIN_H */
