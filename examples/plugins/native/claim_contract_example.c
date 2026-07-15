#include <resymbol_plugin.h>

/*
 * Compile-time example for the additive protocol-1 recovery-claim helpers.
 * A real plugin serializes these values into the tagged JSON envelope passed
 * to host_api->submit_claim; these helper structures do not cross the C ABI.
 */
int resymbol_example_recovery_claim_helpers(void)
{
    static const char text[] = "Recovered ASCII text";
    const char *literal_kind = RESYMBOL_ASSERTION_KIND_STRING_LITERAL;
    const char *reference_kind = RESYMBOL_ASSERTION_KIND_DATA_REFERENCE;
    const char *encoding_name = RESYMBOL_STRING_ENCODING_ASCII_WIRE;
    resymbol_string_literal_assertion_v1 literal = {
        {NULL, UINT64_C(0)},
        (resymbol_string_encoding)0u,
        UINT32_C(0)};
    resymbol_data_reference_assertion_v1 reference = {
        UINT64_C(0),
        UINT64_C(0),
        (uint8_t)0u,
        {(uint8_t)0u, (uint8_t)0u, (uint8_t)0u, (uint8_t)0u,
         (uint8_t)0u, (uint8_t)0u, (uint8_t)0u}};

    literal.value_utf8.data = text;
    literal.value_utf8.length = (uint64_t)(sizeof(text) - 1u);
    literal.encoding = RESYMBOL_STRING_ENCODING_ASCII;

    reference.instruction_rva = UINT64_C(0x1008);
    reference.instruction_size = (uint8_t)7u;
    reference.target_rva = UINT64_C(0x3000);

    if (literal_kind[0] == 's' && reference_kind[0] == 'd' &&
        encoding_name[0] == 'a' && literal.value_utf8.length != 0u &&
        reference.instruction_size != 0u)
    {
        return 0;
    }

    return 1;
}
