#define NOMINMAX

#include <windows.h>

#include <dia2.h>
#include <diacreate.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string_view>

namespace {

constexpr GUID kExpectedGuid = {
    0x00112233,
    0x4455,
    0x6677,
    {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
};
constexpr DWORD kExpectedAge = 7;

template <typename T>
class ComPtr final {
public:
    ComPtr() noexcept = default;
    ~ComPtr() { reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T* get() const noexcept { return value_; }
    T* operator->() const noexcept { return value_; }

    T** put() noexcept {
        reset();
        return &value_;
    }

    void reset() noexcept {
        if (value_ != nullptr) {
            value_->Release();
            value_ = nullptr;
        }
    }

private:
    T* value_ = nullptr;
};

class Bstr final {
public:
    Bstr() noexcept = default;
    ~Bstr() {
        if (value_ != nullptr) {
            SysFreeString(value_);
        }
    }

    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;

    BSTR* put() noexcept { return &value_; }
    BSTR get() const noexcept { return value_; }

private:
    BSTR value_ = nullptr;
};

void report_hresult(std::wstring_view operation, HRESULT result) {
    wchar_t description[512] = {};
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(result),
        0,
        description,
        static_cast<DWORD>(sizeof(description) / sizeof(description[0])),
        nullptr);

    std::wcerr << operation << L" failed with HRESULT 0x" << std::hex
               << std::setw(8) << std::setfill(L'0')
               << static_cast<std::uint32_t>(result) << std::dec;
    if (length != 0) {
        std::wcerr << L": " << description;
    } else {
        std::wcerr << L'\n';
    }
}

HRESULT create_data_source(const wchar_t* dia_dll, ComPtr<IDiaDataSource>& source) {
    HRESULT result = CoCreateInstance(
        __uuidof(DiaSource),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(IDiaDataSource),
        reinterpret_cast<void**>(source.put()));
    if (SUCCEEDED(result) || dia_dll == nullptr) {
        return result;
    }

    std::wcerr << L"Registered DIA activation failed; retrying with " << dia_dll
               << L".\n";
    return NoRegCoCreate(
        dia_dll,
        __uuidof(DiaSource),
        __uuidof(IDiaDataSource),
        reinterpret_cast<void**>(source.put()));
}

bool verify_wrong_age_is_rejected(const wchar_t* pdb_path, const wchar_t* dia_dll) {
    ComPtr<IDiaDataSource> source;
    HRESULT result = create_data_source(dia_dll, source);
    if (FAILED(result)) {
        report_hresult(L"creating DIA data source for negative identity test", result);
        return false;
    }

    GUID guid = kExpectedGuid;
    result = source->loadAndValidateDataFromPdb(
        pdb_path,
        &guid,
        0,
        kExpectedAge + 1);
    if (SUCCEEDED(result)) {
        std::wcerr << L"DIA accepted the PDB with the deliberately wrong age "
                   << (kExpectedAge + 1) << L".\n";
        return false;
    }

    std::wcout << L"DIA rejected the deliberately wrong age (HRESULT 0x"
               << std::hex << std::setw(8) << std::setfill(L'0')
               << static_cast<std::uint32_t>(result) << std::dec << L").\n";
    return true;
}

bool verify_wrong_guid_is_rejected(const wchar_t* pdb_path, const wchar_t* dia_dll) {
    ComPtr<IDiaDataSource> source;
    HRESULT result = create_data_source(dia_dll, source);
    if (FAILED(result)) {
        report_hresult(L"creating DIA data source for wrong-GUID test", result);
        return false;
    }

    GUID guid = kExpectedGuid;
    ++guid.Data1;
    result = source->loadAndValidateDataFromPdb(pdb_path, &guid, 0, kExpectedAge);
    if (SUCCEEDED(result)) {
        std::wcerr << L"DIA accepted the PDB with a deliberately wrong GUID.\n";
        return false;
    }

    std::wcout << L"DIA rejected the deliberately wrong GUID (HRESULT 0x"
               << std::hex << std::setw(8) << std::setfill(L'0')
               << static_cast<std::uint32_t>(result) << std::dec << L").\n";
    return true;
}

struct ExpectedPublic {
    const wchar_t* name;
    DWORD section;
    DWORD offset;
    bool is_function;
    unsigned matches = 0;
};

bool inspect_expected_public(IDiaSymbol* symbol, ExpectedPublic& expected) {
    DWORD section = 0;
    DWORD offset = 0;
    BOOL is_function = FALSE;

    HRESULT result = symbol->get_addressSection(&section);
    if (result != S_OK) {
        report_hresult(L"reading public-symbol address section", result);
        return false;
    }
    result = symbol->get_addressOffset(&offset);
    if (result != S_OK) {
        report_hresult(L"reading public-symbol address offset", result);
        return false;
    }
    result = symbol->get_function(&is_function);
    if (result != S_OK) {
        report_hresult(L"reading public-symbol function flag", result);
        return false;
    }

    if (section != expected.section || offset != expected.offset ||
        (is_function != FALSE) != expected.is_function) {
        std::wcerr << L"Unexpected DIA properties for " << expected.name
                   << L": got section " << section << L", offset 0x" << std::hex
                   << offset << std::dec << L", function="
                   << ((is_function != FALSE) ? L"true" : L"false")
                   << L"; expected section " << expected.section << L", offset 0x"
                   << std::hex << expected.offset << std::dec << L", function="
                   << (expected.is_function ? L"true" : L"false") << L".\n";
        return false;
    }

    ++expected.matches;
    return true;
}

bool symbol_has_name(IDiaSymbol* symbol, const wchar_t* expected) {
    Bstr name;
    const HRESULT result = symbol->get_name(name.put());
    if (result != S_OK || name.get() == nullptr) {
        report_hresult(L"reading DIA public-symbol name", result);
        return false;
    }
    return std::wstring_view(name.get(), SysStringLen(name.get())) ==
           std::wstring_view(expected);
}

bool verify_exact_name_lookup(IDiaSymbol* global_scope, ExpectedPublic expected) {
    expected.matches = 0;
    ComPtr<IDiaEnumSymbols> matches;
    HRESULT result = global_scope->findChildren(
        SymTagPublicSymbol,
        expected.name,
        nsfCaseSensitive,
        matches.put());
    if (FAILED(result)) {
        report_hresult(L"performing exact DIA public-name lookup", result);
        return false;
    }

    for (;;) {
        ComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        result = matches->Next(1, symbol.put(), &fetched);
        if (result == S_FALSE || fetched == 0) {
            break;
        }
        if (result != S_OK || fetched != 1) {
            report_hresult(L"enumerating exact DIA public-name lookup", result);
            return false;
        }
        if (!symbol_has_name(symbol.get(), expected.name) ||
            !inspect_expected_public(symbol.get(), expected)) {
            return false;
        }
    }

    if (expected.matches != 1) {
        std::wcerr << L"Exact DIA lookup for " << expected.name << L" returned "
                   << expected.matches << L" matches instead of one.\n";
        return false;
    }
    return true;
}

bool verify_address_lookup(IDiaSession* session, ExpectedPublic expected) {
    expected.matches = 0;
    ComPtr<IDiaSymbol> symbol;
    const HRESULT result = session->findSymbolByAddr(
        expected.section,
        expected.offset,
        SymTagPublicSymbol,
        symbol.put());
    if (result != S_OK) {
        report_hresult(L"performing DIA public address lookup", result);
        return false;
    }
    if (!symbol_has_name(symbol.get(), expected.name) ||
        !inspect_expected_public(symbol.get(), expected)) {
        return false;
    }
    return expected.matches == 1;
}

bool verify_publics(IDiaSession* session) {
    ComPtr<IDiaSymbol> global_scope;
    HRESULT result = session->get_globalScope(global_scope.put());
    if (FAILED(result)) {
        report_hresult(L"opening DIA global scope", result);
        return false;
    }

    ComPtr<IDiaEnumSymbols> publics;
    result = global_scope->findChildren(
        SymTagPublicSymbol,
        nullptr,
        nsNone,
        publics.put());
    if (FAILED(result)) {
        report_hresult(L"enumerating DIA public symbols", result);
        return false;
    }

    ExpectedPublic expected[] = {
        {L"reconstructed_function", 1, 0x20, true},
        {L"reconstructed_global", 2, 0x10, false},
    };

    unsigned total_publics = 0;
    for (;;) {
        ComPtr<IDiaSymbol> symbol;
        ULONG fetched = 0;
        result = publics->Next(1, symbol.put(), &fetched);
        if (result == S_FALSE || fetched == 0) {
            break;
        }
        if (FAILED(result)) {
            report_hresult(L"reading DIA public-symbol enumeration", result);
            return false;
        }
        if (result != S_OK || fetched != 1) {
            std::wcerr << L"DIA returned an unexpected public-symbol enumeration result.\n";
            return false;
        }
        ++total_publics;

        Bstr name;
        result = symbol->get_name(name.put());
        if (result != S_OK || name.get() == nullptr) {
            report_hresult(L"reading DIA public-symbol name", result);
            return false;
        }

        const std::wstring_view actual(name.get(), SysStringLen(name.get()));
        for (ExpectedPublic& candidate : expected) {
            if (actual == std::wstring_view(candidate.name) &&
                !inspect_expected_public(symbol.get(), candidate)) {
                return false;
            }
        }
    }

    for (const ExpectedPublic& candidate : expected) {
        if (candidate.matches != 1) {
            std::wcerr << L"Expected exactly one DIA public named " << candidate.name
                       << L", found " << candidate.matches << L".\n";
            return false;
        }
    }
    if (total_publics != 2) {
        std::wcerr << L"Expected exactly two DIA public symbols, found "
                   << total_publics << L".\n";
        return false;
    }

    for (const ExpectedPublic& candidate : expected) {
        if (!verify_exact_name_lookup(global_scope.get(), candidate) ||
            !verify_address_lookup(session, candidate)) {
            return false;
        }
    }

    std::wcout << L"DIA enumerated and found both expected publics by exact name "
                  L"and address with exact section, offset, and function flags.\n";
    return true;
}

bool verify_exact_identity_and_publics(const wchar_t* pdb_path, const wchar_t* dia_dll) {
    ComPtr<IDiaDataSource> source;
    HRESULT result = create_data_source(dia_dll, source);
    if (FAILED(result)) {
        report_hresult(L"creating DIA data source", result);
        return false;
    }

    GUID guid = kExpectedGuid;
    result = source->loadAndValidateDataFromPdb(pdb_path, &guid, 0, kExpectedAge);
    if (FAILED(result)) {
        report_hresult(L"validating exact PDB GUID/signature/age", result);
        return false;
    }

    ComPtr<IDiaSession> session;
    result = source->openSession(session.put());
    if (FAILED(result)) {
        report_hresult(L"opening DIA session", result);
        return false;
    }

    return verify_publics(session.get());
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2 && argc != 3) {
        std::wcerr << L"Usage: dia_probe.exe <pdb-path> [msdia140.dll-path]\n";
        return 2;
    }

    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) {
        report_hresult(L"initializing COM", initialized);
        return 1;
    }

    const wchar_t* const dia_dll = argc == 3 ? argv[2] : nullptr;
    const bool wrong_age_rejected = verify_wrong_age_is_rejected(argv[1], dia_dll);
    const bool wrong_guid_rejected =
        wrong_age_rejected && verify_wrong_guid_is_rejected(argv[1], dia_dll);
    const bool exact_identity_valid =
        wrong_guid_rejected && verify_exact_identity_and_publics(argv[1], dia_dll);

    CoUninitialize();
    if (!exact_identity_valid) {
        return 1;
    }

    std::wcout << L"DIA compatibility probe passed.\n";
    return 0;
}
