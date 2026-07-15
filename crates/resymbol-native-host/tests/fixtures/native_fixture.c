#define RESYMBOL_PLUGIN_BUILD 1
#include <resymbol_plugin.h>

#include <stdio.h>
#include <string.h>

typedef struct fixture_context {
    const resymbol_host_api_v1 *host;
} fixture_context;

static fixture_context fixture = {NULL};
static const char fixture_id[] = "dev.resymbol.native-fixture";
static const char fixture_name[] = "Native host fixture";
static const char fixture_version[] = "0.1.0";
static const char fixture_capabilities[] = "[\"analyzer.binary\"]";
static const char fixture_permissions[] =
    "[\"binary.read\",\"claims.submit\"]";

static resymbol_string_view fixture_string(const char *value)
{
    resymbol_string_view view;
    view.data = value;
    view.length = (uint64_t)strlen(value);
    return view;
}

static resymbol_byte_view fixture_bytes(const char *value)
{
    resymbol_byte_view view;
    view.data = (const uint8_t *)value;
    view.length = (uint64_t)strlen(value);
    return view;
}

static resymbol_status RESYMBOL_PLUGIN_CALL fixture_get_descriptor(
    void *plugin_context,
    resymbol_plugin_descriptor_v1 *descriptor) RESYMBOL_PLUGIN_NOEXCEPT
{
    (void)plugin_context;
    if (descriptor == NULL ||
        descriptor->struct_size < sizeof(resymbol_plugin_descriptor_v1))
    {
        return RESYMBOL_STATUS_INVALID_ARGUMENT;
    }
    descriptor->struct_size = (uint32_t)sizeof(*descriptor);
    descriptor->abi_version = RESYMBOL_PLUGIN_ABI_VERSION;
    descriptor->id = fixture_string(fixture_id);
    descriptor->name = fixture_string(fixture_name);
    descriptor->version = fixture_string(fixture_version);
    descriptor->isolation = RESYMBOL_ISOLATION_OUT_OF_PROCESS;
    descriptor->capabilities_json_utf8 = fixture_bytes(fixture_capabilities);
    descriptor->requested_permissions_json_utf8 =
        fixture_bytes(fixture_permissions);
    return RESYMBOL_STATUS_OK;
}

static resymbol_status RESYMBOL_PLUGIN_CALL fixture_initialize(
    void *plugin_context,
    resymbol_byte_view init_json_utf8) RESYMBOL_PLUGIN_NOEXCEPT
{
    fixture_context *context = (fixture_context *)plugin_context;
    uint8_t magic[2] = {0u, 0u};
    uint64_t bytes_read = 0u;
    resymbol_mut_byte_span destination = {magic, 2u};
    resymbol_string_view message = fixture_string("native fixture initialized");
    (void)init_json_utf8;

    if (context == NULL || context->host == NULL)
    {
        return RESYMBOL_STATUS_INTERNAL_ERROR;
    }
    if (context->host->read_binary(
            context->host->host_context, 0u, destination, &bytes_read) !=
            RESYMBOL_STATUS_OK ||
        bytes_read != 2u || magic[0] != (uint8_t)'M' ||
        magic[1] != (uint8_t)'Z')
    {
        return RESYMBOL_STATUS_INVALID_ARGUMENT;
    }
    context->host->log(
        context->host->host_context, RESYMBOL_LOG_INFO, message);
    return RESYMBOL_STATUS_OK;
}

static int fixture_binary_id(
    resymbol_byte_view request,
    char destination[65])
{
    static const char marker[] = "\"id\":\"";
    size_t index;
    size_t marker_size = sizeof(marker) - 1u;
    size_t request_size = (size_t)request.length;

    if (request.data == NULL || request.length > (uint64_t)SIZE_MAX ||
        request_size < marker_size + 64u)
    {
        return 0;
    }
    for (index = 0u; index + marker_size + 64u <= request_size; ++index)
    {
        if (memcmp(request.data + index, marker, marker_size) == 0)
        {
            size_t digit;
            int valid = 1;
            for (digit = 0u; digit < 64u; ++digit)
            {
                uint8_t value = request.data[index + marker_size + digit];
                if (!((value >= (uint8_t)'0' && value <= (uint8_t)'9') ||
                      (value >= (uint8_t)'a' && value <= (uint8_t)'f')))
                {
                    valid = 0;
                    break;
                }
                destination[digit] = (char)value;
            }
            if (valid)
            {
                destination[64] = '\0';
                return 1;
            }
        }
    }
    return 0;
}

static resymbol_status RESYMBOL_PLUGIN_CALL fixture_analyze(
    void *plugin_context,
    resymbol_byte_view request_json_utf8) RESYMBOL_PLUGIN_NOEXCEPT
{
    fixture_context *context = (fixture_context *)plugin_context;
    char binary_id[65];
    char claim[768];
    int length;
    resymbol_byte_view claim_view;

    if (context == NULL || context->host == NULL ||
        !fixture_binary_id(request_json_utf8, binary_id))
    {
        return RESYMBOL_STATUS_INVALID_ARGUMENT;
    }
    length = snprintf(
        claim,
        sizeof(claim),
        "{\"subject\":{\"kind\":\"function\",\"binary\":\"%s\","
        "\"rva\":0,\"size\":1},\"claim\":{\"kind\":\"name\","
        "\"name\":\"native_fixture\"},\"confidence\":0.9,"
        "\"evidence\":[{\"kind\":\"signature-match\","
        "\"description\":\"native fixture callback\"}]}",
        binary_id);
    if (length < 0 || (size_t)length >= sizeof(claim))
    {
        return RESYMBOL_STATUS_RESOURCE_LIMIT;
    }
    claim_view.data = (const uint8_t *)claim;
    claim_view.length = (uint64_t)length;
    return context->host->submit_claim(
        context->host->host_context, claim_view);
}

static resymbol_status RESYMBOL_PLUGIN_CALL fixture_health_check(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    return plugin_context == NULL ? RESYMBOL_STATUS_INVALID_ARGUMENT
                                  : RESYMBOL_STATUS_OK;
}

static void RESYMBOL_PLUGIN_CALL fixture_shutdown(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    (void)plugin_context;
}

static void RESYMBOL_PLUGIN_CALL fixture_destroy(
    void *plugin_context) RESYMBOL_PLUGIN_NOEXCEPT
{
    (void)plugin_context;
}

RESYMBOL_PLUGIN_EXPORT resymbol_status RESYMBOL_PLUGIN_CALL
resymbol_plugin_get_api(
    uint32_t requested_abi_version,
    const resymbol_host_api_v1 *host_api,
    resymbol_plugin_api_v1 *plugin_api) RESYMBOL_PLUGIN_NOEXCEPT
{
    if (requested_abi_version != RESYMBOL_PLUGIN_ABI_VERSION ||
        host_api == NULL || plugin_api == NULL ||
        host_api->struct_size < sizeof(resymbol_host_api_v1) ||
        plugin_api->struct_size < sizeof(resymbol_plugin_api_v1))
    {
        return RESYMBOL_STATUS_INCOMPATIBLE_ABI;
    }
    fixture.host = host_api;
    plugin_api->struct_size = (uint32_t)sizeof(*plugin_api);
    plugin_api->abi_version = RESYMBOL_PLUGIN_ABI_VERSION;
    plugin_api->plugin_context = &fixture;
    plugin_api->get_descriptor = fixture_get_descriptor;
    plugin_api->initialize = fixture_initialize;
    plugin_api->analyze = fixture_analyze;
    plugin_api->health_check = fixture_health_check;
    plugin_api->shutdown = fixture_shutdown;
    plugin_api->destroy = fixture_destroy;
    return RESYMBOL_STATUS_OK;
}
