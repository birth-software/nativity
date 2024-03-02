#include "lld/Common/CommonLinkerContext.h"
using namespace llvm;

enum class Format {
    elf = 0,
    macho = 1,
    coff = 2,
};

namespace lld {
    namespace coff {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace elf {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace wasm {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
    namespace macho {
        bool link(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS,
                llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput);
    }
}

extern "C" void stream_to_string(raw_string_ostream& stream, const char** message_ptr, size_t* message_len);

extern "C" bool NativityLLDLinkELF(const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = lld::elf::link(arguments, stdout_stream, stderr_stream, true, false);

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}

extern "C" bool NativityLLDLinkCOFF(const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = lld::coff::link(arguments, stdout_stream, stderr_stream, true, false);

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}

extern "C" bool NativityLLDLinkMachO(const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = lld::macho::link(arguments, stdout_stream, stderr_stream, true, false);

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}

extern "C" bool NativityLLDLinkWasm(const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = lld::wasm::link(arguments, stdout_stream, stderr_stream, true, false);

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}
