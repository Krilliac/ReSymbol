#define RESYMBOL_PLUGIN_BUILD 1
#include <resymbol_plugin.h>

/*
 * Minimal C++11 native plugin showing the exception-safe ABI boundary. The
 * descriptor matches plugin.toml. Real analysis work can throw internally as
 * long as each exported lifecycle callback translates failures before they
 * reach the C ABI.
 */
namespace {

struct example_context
{
    const resymbol_host_api_v1 *host;
};

example_context context = {NULL};

template <size_t Size>
resymbol_string_view string_view(const char (&value)[Size])
    RESYMBOL_PLUGIN_NOEXCEPT
{
    resymbol_string_view view = {value, static_cast<uint64_t>(Size - 1u)};
    return view;
}

template <size_t Size>
resymbol_byte_view byte_view(const char (&value)[Size])
    RESYMBOL_PLUGIN_NOEXCEPT
{
    resymbol_byte_view view = {
        reinterpret_cast<const uint8_t *>(value),
        static_cast<uint64_t>(Size - 1u)};
    return view;
}

resymbol_status RESYMBOL_PLUGIN_CALL get_descriptor(
    void *plugin_context,
    resymbol_plugin_descriptor_v1 *descriptor) RESYMBOL_PLUGIN_NOEXCEPT
{
    return resymbol_plugin_cpp::catch_to_status(
        [plugin_context, descriptor]() -> resymbol_status {
            static const char id[] = "dev.resymbol.example.native-rtti";
            static const char name[] = "Example Native RTTI Resolver";
            static const char version[] = "0.1.0";
            static const char capabilities[] =
                "[\"analyzer.rtti\",\"resolver.symbols\"]";
            static const char permissions[] =
                "[\"binary.read\",\"claims.submit\"]";

            if (plugin_context != &context || descriptor == NULL ||
                descriptor->struct_size <
                    sizeof(resymbol_plugin_descriptor_v1))
            {
                return RESYMBOL_STATUS_INVALID_ARGUMENT;
            }

            resymbol_plugin_descriptor_v1 result = {};
            result.struct_size = static_cast<uint32_t>(sizeof(result));
            result.abi_version = RESYMBOL_PLUGIN_ABI_VERSION;
            result.id = string_view(id);
            result.name = string_view(name);
            result.version = string_view(version);
            result.isolation = RESYMBOL_ISOLATION_OUT_OF_PROCESS;
            result.capabilities_json_utf8 = byte_view(capabilities);
            result.requested_permissions_json_utf8 = byte_view(permissions);
            *descriptor = result;
            return RESYMBOL_STATUS_OK;
        });
}

resymbol_status RESYMBOL_PLUGIN_CALL initialize(
    void *plugin_context,
    resymbol_byte_view init_json_utf8) RESYMBOL_PLUGIN_NOEXCEPT
{
    return resymbol_plugin_cpp::catch_to_status(
        [plugin_context, init_json_utf8]() -> resymbol_status {
            if (plugin_context != &context || context.host == NULL ||
                (init_json_utf8.length != 0u &&
                 init_json_utf8.data == NULL))
            {
                return RESYMBOL_STATUS_INVALID_ARGUMENT;
            }
            return RESYMBOL_STATUS_OK;
        });
}

resymbol_status RESYMBOL_PLUGIN_CALL analyze(
    void *plugin_context,
    resymbol_byte_view request_json_utf8) RESYMBOL_PLUGIN_NOEXCEPT
{
    return resymbol_plugin_cpp::catch_to_status(
        [plugin_context, request_json_utf8]() -> resymbol_status {
            static const char message[] =
                "C++ native example received an analysis request";

            if (plugin_context != &context || context.host == NULL ||
                context.host->log == NULL ||
                (request_json_utf8.length != 0u &&
                 request_json_utf8.data == NULL))
            {
                return RESYMBOL_STATUS_INVALID_ARGUMENT;
            }

            context.host->log(
                context.host->host_context,
                RESYMBOL_LOG_INFO,
                string_view(message));
            return RESYMBOL_STATUS_OK;
        });
}

resymbol_status RESYMBOL_PLUGIN_CALL health_check(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    return resymbol_plugin_cpp::catch_to_status(
        [plugin_context]() -> resymbol_status {
            return plugin_context == &context && context.host != NULL
                       ? RESYMBOL_STATUS_OK
                       : RESYMBOL_STATUS_UNAVAILABLE;
        });
}

void RESYMBOL_PLUGIN_CALL shutdown(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    resymbol_plugin_cpp::catch_all([plugin_context]() {
        if (plugin_context == &context)
        {
            /* Join plugin-owned workers and release session state here. */
        }
    });
}

void RESYMBOL_PLUGIN_CALL destroy(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    resymbol_plugin_cpp::catch_all([plugin_context]() {
        if (plugin_context == &context)
        {
            context.host = NULL;
        }
    });
}

} /* namespace */

RESYMBOL_PLUGIN_EXPORT resymbol_status RESYMBOL_PLUGIN_CALL
resymbol_plugin_get_api(
    uint32_t requested_abi_version,
    const resymbol_host_api_v1 *host_api,
    resymbol_plugin_api_v1 *plugin_api) RESYMBOL_PLUGIN_NOEXCEPT
{
    return resymbol_plugin_cpp::catch_to_status(
        [requested_abi_version, host_api, plugin_api]() -> resymbol_status {
            if (requested_abi_version != RESYMBOL_PLUGIN_ABI_VERSION ||
                host_api == NULL || plugin_api == NULL ||
                host_api->struct_size < sizeof(resymbol_host_api_v1) ||
                plugin_api->struct_size < sizeof(resymbol_plugin_api_v1))
            {
                return RESYMBOL_STATUS_INCOMPATIBLE_ABI;
            }

            context.host = host_api;
            plugin_api->struct_size =
                static_cast<uint32_t>(sizeof(*plugin_api));
            plugin_api->abi_version = RESYMBOL_PLUGIN_ABI_VERSION;
            plugin_api->plugin_context = &context;
            plugin_api->get_descriptor = &get_descriptor;
            plugin_api->initialize = &initialize;
            plugin_api->analyze = &analyze;
            plugin_api->health_check = &health_check;
            plugin_api->shutdown = &shutdown;
            plugin_api->destroy = &destroy;
            return RESYMBOL_STATUS_OK;
        });
}
