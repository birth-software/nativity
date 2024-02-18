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

extern "C" bool NativityLLDLink(Format format, const char** argument_ptr, size_t argument_count, const char** stdout_ptr, size_t* stdout_len, const char** stderr_ptr, size_t* stderr_len)
{
    auto arguments = ArrayRef<const char*>(argument_ptr, argument_count);
    std::string stdout_string;
    raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    raw_string_ostream stderr_stream(stderr_string);

    bool success = false;
    switch (format) {
        case Format::elf:
            success = lld::elf::link(arguments, stdout_stream, stderr_stream, true, false);
            break;
        case Format::coff:
            success = lld::coff::link(arguments, stdout_stream, stderr_stream, true, false);
        case Format::macho:
            success = lld::macho::link(arguments, stdout_stream, stderr_stream, true, false);
        default:
            break;
    }

    stream_to_string(stdout_stream, stdout_ptr, stdout_len);
    stream_to_string(stderr_stream, stderr_ptr, stderr_len);

    return success;
}

