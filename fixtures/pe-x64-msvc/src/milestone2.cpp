// Dual-licensed under MIT or Apache-2.0, matching ReSymbol.
//
// This program is intentionally tiny and self-contained. It is never executed
// by the test suite; its PE metadata and machine code are analyzer fixtures.

extern "C" __declspec(dllimport) unsigned long __stdcall GetTickCount();
extern "C" __declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(
    unsigned int exit_code);

extern "C" __declspec(dllexport) const volatile char fixture_ascii[] =
    "ReSymbol fixture ASCII sentinel!";
extern "C" __declspec(dllexport) const volatile wchar_t fixture_utf16[] =
    L"ReSymbol fixture UTF16 sentinel";
extern "C" __declspec(dllexport) volatile int fixture_sink = 0;

namespace resymbol_fixture {

class Base {
public:
    virtual int Evaluate(int value) noexcept;
};

class Derived final : public Base {
public:
    int Evaluate(int value) noexcept override;
    virtual int Extra(int value) noexcept;
};

__declspec(noinline) int Base::Evaluate(int value) noexcept {
    return value + 11;
}

__declspec(noinline) int Derived::Evaluate(int value) noexcept {
    return value * 3 + 7;
}

__declspec(noinline) int Derived::Extra(int value) noexcept {
    return value ^ 0x5a5a;
}

} // namespace resymbol_fixture

extern "C" __declspec(dllexport) __declspec(noinline) int fixture_leaf(
    int value) noexcept {
    return value * 5 + 3;
}

extern "C" __declspec(dllexport) __declspec(noinline) int fixture_string_score(
    int value) noexcept {
    // The volatile stack anchor forces a real unwind-covered function body so
    // ReSymbol's bounded runtime-function sweep observes the fixed data reads.
    volatile int stack_anchor[4] = {value, 0, 0, 0};
    const unsigned int index = static_cast<unsigned int>(value) & 7U;
    const int fixed_references = static_cast<int>(fixture_ascii[0]) +
                                 static_cast<int>(fixture_utf16[0]);
    return fixed_references + static_cast<int>(fixture_ascii[index]) +
           static_cast<int>(fixture_utf16[index]) + stack_anchor[0] - value;
}

extern "C" __declspec(dllexport) __declspec(noinline) int fixture_caller(
    int value) noexcept {
    const int recovered_call = fixture_leaf(value + 7);
    return recovered_call + fixture_string_score(value);
}

// Under the pinned optimized build this becomes a one-instruction relative
// jump and exercises internal-thunk recovery.
extern "C" __declspec(dllexport) __declspec(noinline) int fixture_thunk(
    int value) noexcept {
    return fixture_leaf(value);
}

// This becomes a one-instruction RIP-relative jump through the import table
// and exercises import-thunk recovery.
extern "C" __declspec(dllexport) __declspec(noinline) unsigned long
fixture_import_thunk() noexcept {
    return GetTickCount();
}

extern "C" __declspec(dllexport) __declspec(noinline) int
fixture_virtual_dispatch(resymbol_fixture::Base* object, int value) noexcept {
    return object->Evaluate(value);
}

extern "C" __declspec(noreturn) void fixture_entry() noexcept {
    resymbol_fixture::Derived object;
    const int seed = static_cast<int>(GetTickCount());
    const int result = fixture_caller(seed) + fixture_thunk(seed) +
                       fixture_virtual_dispatch(&object, seed) +
                       static_cast<int>(fixture_import_thunk());
    fixture_sink = result;
    ExitProcess(static_cast<unsigned int>(result) & 0xffU);
}
