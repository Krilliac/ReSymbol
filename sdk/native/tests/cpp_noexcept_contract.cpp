#include <resymbol_plugin.h>

#include <type_traits>

struct status_operation
{
    resymbol_status operator()() const;
};

struct void_operation
{
    void operator()() const;
};

static_assert(
    noexcept(resymbol_plugin_cpp::catch_to_status(status_operation{})),
    "the status exception guard must itself be non-throwing");
static_assert(
    noexcept(resymbol_plugin_cpp::catch_all(void_operation{})),
    "the void exception guard must itself be non-throwing");

resymbol_status RESYMBOL_PLUGIN_CALL safe_descriptor(
    void *,
    resymbol_plugin_descriptor_v1 *) RESYMBOL_PLUGIN_NOEXCEPT;

static_assert(
    noexcept(safe_descriptor(
        static_cast<void *>(NULL),
        static_cast<resymbol_plugin_descriptor_v1 *>(NULL))),
    "callback definitions must use RESYMBOL_PLUGIN_NOEXCEPT");
static_assert(
    std::is_convertible<
        decltype(&safe_descriptor),
        resymbol_plugin_get_descriptor_fn>::value,
    "a noexcept lifecycle callback must be assignable");

#if __cplusplus >= 201703L
static_assert(
    noexcept(static_cast<resymbol_plugin_get_descriptor_fn>(nullptr)(
        static_cast<void *>(NULL),
        static_cast<resymbol_plugin_descriptor_v1 *>(NULL))),
    "C++17 get_descriptor type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_initialize_fn>(nullptr)(
        static_cast<void *>(NULL),
        resymbol_byte_view{})),
    "C++17 initialize type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_analyze_fn>(nullptr)(
        static_cast<void *>(NULL),
        resymbol_byte_view{})),
    "C++17 analyze type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_health_check_fn>(nullptr)(
        static_cast<void *>(NULL))),
    "C++17 health_check type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_shutdown_fn>(nullptr)(
        static_cast<void *>(NULL))),
    "C++17 shutdown type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_destroy_fn>(nullptr)(
        static_cast<void *>(NULL))),
    "C++17 destroy type must be non-throwing");
static_assert(
    noexcept(static_cast<resymbol_plugin_get_api_fn>(nullptr)(
        UINT32_C(0),
        static_cast<const resymbol_host_api_v1 *>(NULL),
        static_cast<resymbol_plugin_api_v1 *>(NULL))),
    "C++17 entrypoint type must be non-throwing");

resymbol_status RESYMBOL_PLUGIN_CALL potentially_throwing_descriptor(
    void *,
    resymbol_plugin_descriptor_v1 *);

static_assert(
    !std::is_convertible<
        decltype(&potentially_throwing_descriptor),
        resymbol_plugin_get_descriptor_fn>::value,
    "C++17 must reject a potentially-throwing lifecycle callback");
#endif
