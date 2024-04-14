const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");
const arch = builtin.cpu.arch;
const os = builtin.os.tag;

fn discover_brew_prefix(b: *std.Build, library_name: []const u8) ![]const u8 {
    assert(os == .macos);
    const result = try std.ChildProcess.run(.{
        .allocator = b.allocator,
        .argv = &.{ "brew", "--prefix", library_name },
    });

    var i = result.stdout.len - 1;
    while (result.stdout[i] == '\n' or result.stdout[i] == ' ') {
        i -= 1;
    }
    const trimmed_path = result.stdout[0 .. i + 1];
    return trimmed_path;
}

pub fn build(b: *std.Build) !void {
    const self_hosted_ci = b.option(bool, "self_hosted_ci", "This option enables the self-hosted CI behavior") orelse false;
    const third_party_ci = b.option(bool, "third_party_ci", "This option enables the third-party CI behavior") orelse false;
    const is_ci = self_hosted_ci or third_party_ci;
    const print_stack_trace = b.option(bool, "print_stack_trace", "This option enables printing stack traces inside the compiler") orelse is_ci; //or os == .macos;
    const native_target = b.resolveTargetQuery(.{});
    const optimization = b.standardOptimizeOption(.{});
    const use_debug = b.option(bool, "use_debug", "This option enables the LLVM debug build in the development PC") orelse false;
    const static = b.option(bool, "static", "This option enables the compiler to be built statically") orelse switch (@import("builtin").os.tag) {
        else => use_debug,
        .macos => true,
    };
    const compiler_options = b.addOptions();
    compiler_options.addOption(bool, "print_stack_trace", print_stack_trace);

    const fetcher = b.addExecutable(.{
        .name = "llvm_fetcher",
        .root_source_file = .{ .path = "build/fetcher.zig" },
        .target = native_target,
        .optimize = .Debug,
        .single_threaded = true,
    });

    var target_query = b.standardTargetOptionsQueryOnly(.{});
    const abi = b.option(std.Target.Abi, "abi", "This option modifies the ABI used for the compiler") orelse if (static) switch (target_query.os_tag orelse @import("builtin").os.tag) {
        else => target_query.abi,
        .linux => b: {
            const os_release = try std.fs.cwd().readFileAlloc(b.allocator, "/etc/os-release", 0xffff);
            const attribute_name = "ID=";
            const i = std.mem.indexOf(u8, os_release, attribute_name) orelse unreachable;
            const maybe_start_quote_index = i + attribute_name.len;
            const value = if (os_release[maybe_start_quote_index] == '\"') attr: {
                const end_quote_index = std.mem.indexOf(u8, os_release[maybe_start_quote_index + 1 ..], "\"") orelse unreachable;
                const attribute_value = os_release[maybe_start_quote_index + 1 ..][0..end_quote_index];
                break :attr attribute_value;
            } else attr: {
                const line_feed = std.mem.indexOf(u8, os_release[maybe_start_quote_index..], "\n") orelse unreachable;
                const attribute_value = os_release[maybe_start_quote_index..][0..line_feed];
                break :attr attribute_value;
            };
            break :b if (std.mem.eql(u8, value, "arch") or std.mem.eql(u8, value, "endeavouros")) .musl else target_query.abi;
        },
    } else target_query.abi;
    target_query.abi = abi;
    const target = b.resolveTargetQuery(target_query);

    const compiler = b.addExecutable(.{
        .name = "nat",
        .root_source_file = .{ .path = "bootstrap/main.zig" },
        .target = target,
        .optimize = optimization,
    });

    const cpp_files = .{
        "src/llvm/llvm.cpp",
        "src/llvm/lld.cpp",
        "src/llvm/clang_main.cpp",
        "src/llvm/clang_cc1.cpp",
        "src/llvm/clang_cc1as.cpp",
        "src/llvm/ar.cpp",
    };

    compiler.addCSourceFiles(.{
        .files = &cpp_files,
        .flags = &.{
            "-g",
            "-std=c++17",
            "-D__STDC_CONSTANT_MACROS",
            "-D__STDC_FORMAT_MACROS",
            "-D__STDC_LIMIT_MACROS",
            "-D_GNU_SOURCE",
            "-fvisibility-inlines-hidden",
            "-fno-exceptions",
            "-fno-rtti",
            "-Werror=type-limits",
            "-Wno-missing-braces",
            "-Wno-comment",
        },
    });

    compiler.root_module.addOptions("configuration", compiler_options);
    compiler.formatted_panics = print_stack_trace;
    compiler.root_module.unwind_tables = print_stack_trace;
    compiler.root_module.omit_frame_pointer = false;
    compiler.root_module.error_tracing = print_stack_trace;
    compiler.want_lto = false;

    compiler.linkLibC();
    if (target.result.os.tag == .windows) compiler.linkage = .dynamic;

    const zstd = if (target.result.os.tag == .windows) "zstd.lib" else "libzstd.a";

    const static_llvm_libraries = [_][]const u8{
        "libLLVMAArch64AsmParser.a",
        "libLLVMAArch64CodeGen.a",
        "libLLVMAArch64Desc.a",
        "libLLVMAArch64Disassembler.a",
        "libLLVMAArch64Info.a",
        "libLLVMAArch64Utils.a",
        "libLLVMAggressiveInstCombine.a",
        "libLLVMAMDGPUAsmParser.a",
        "libLLVMAMDGPUCodeGen.a",
        "libLLVMAMDGPUDesc.a",
        "libLLVMAMDGPUDisassembler.a",
        "libLLVMAMDGPUInfo.a",
        "libLLVMAMDGPUTargetMCA.a",
        "libLLVMAMDGPUUtils.a",
        "libLLVMAnalysis.a",
        "libLLVMARMAsmParser.a",
        "libLLVMARMCodeGen.a",
        "libLLVMARMDesc.a",
        "libLLVMARMDisassembler.a",
        "libLLVMARMInfo.a",
        "libLLVMARMUtils.a",
        "libLLVMAsmParser.a",
        "libLLVMAsmPrinter.a",
        "libLLVMAVRAsmParser.a",
        "libLLVMAVRCodeGen.a",
        "libLLVMAVRDesc.a",
        "libLLVMAVRDisassembler.a",
        "libLLVMAVRInfo.a",
        "libLLVMBinaryFormat.a",
        "libLLVMBitReader.a",
        "libLLVMBitstreamReader.a",
        "libLLVMBitWriter.a",
        "libLLVMBPFAsmParser.a",
        "libLLVMBPFCodeGen.a",
        "libLLVMBPFDesc.a",
        "libLLVMBPFDisassembler.a",
        "libLLVMBPFInfo.a",
        "libLLVMCFGuard.a",
        "libLLVMCFIVerify.a",
        "libLLVMCodeGen.a",
        "libLLVMCodeGenTypes.a",
        "libLLVMCore.a",
        "libLLVMCoroutines.a",
        "libLLVMCoverage.a",
        "libLLVMDebugInfoBTF.a",
        "libLLVMDebugInfoCodeView.a",
        "libLLVMDebuginfod.a",
        "libLLVMDebugInfoDWARF.a",
        "libLLVMDebugInfoGSYM.a",
        "libLLVMDebugInfoLogicalView.a",
        "libLLVMDebugInfoMSF.a",
        "libLLVMDebugInfoPDB.a",
        "libLLVMDemangle.a",
        "libLLVMDiff.a",
        "libLLVMDlltoolDriver.a",
        "libLLVMDWARFLinker.a",
        "libLLVMDWARFLinkerParallel.a",
        "libLLVMDWP.a",
        "libLLVMExecutionEngine.a",
        "libLLVMExtensions.a",
        "libLLVMFileCheck.a",
        "libLLVMFrontendHLSL.a",
        "libLLVMFrontendOpenACC.a",
        "libLLVMFrontendOpenMP.a",
        "libLLVMFuzzerCLI.a",
        "libLLVMFuzzMutate.a",
        "libLLVMGlobalISel.a",
        "libLLVMHexagonAsmParser.a",
        "libLLVMHexagonCodeGen.a",
        "libLLVMHexagonDesc.a",
        "libLLVMHexagonDisassembler.a",
        "libLLVMHexagonInfo.a",
        "libLLVMInstCombine.a",
        "libLLVMInstrumentation.a",
        "libLLVMInterfaceStub.a",
        "libLLVMInterpreter.a",
        "libLLVMipo.a",
        "libLLVMIRPrinter.a",
        "libLLVMIRReader.a",
        "libLLVMJITLink.a",
        "libLLVMLanaiAsmParser.a",
        "libLLVMLanaiCodeGen.a",
        "libLLVMLanaiDesc.a",
        "libLLVMLanaiDisassembler.a",
        "libLLVMLanaiInfo.a",
        "libLLVMLibDriver.a",
        "libLLVMLineEditor.a",
        "libLLVMLinker.a",
        "libLLVMLoongArchAsmParser.a",
        "libLLVMLoongArchCodeGen.a",
        "libLLVMLoongArchDesc.a",
        "libLLVMLoongArchDisassembler.a",
        "libLLVMLoongArchInfo.a",
        "libLLVMLTO.a",
        "libLLVMMC.a",
        "libLLVMMCA.a",
        "libLLVMMCDisassembler.a",
        "libLLVMMCJIT.a",
        "libLLVMMCParser.a",
        "libLLVMMipsAsmParser.a",
        "libLLVMMipsCodeGen.a",
        "libLLVMMipsDesc.a",
        "libLLVMMipsDisassembler.a",
        "libLLVMMipsInfo.a",
        "libLLVMMIRParser.a",
        "libLLVMMSP430AsmParser.a",
        "libLLVMMSP430CodeGen.a",
        "libLLVMMSP430Desc.a",
        "libLLVMMSP430Disassembler.a",
        "libLLVMMSP430Info.a",
        "libLLVMNVPTXCodeGen.a",
        "libLLVMNVPTXDesc.a",
        "libLLVMNVPTXInfo.a",
        "libLLVMObjCARCOpts.a",
        "libLLVMObjCopy.a",
        "libLLVMObject.a",
        "libLLVMObjectYAML.a",
        "libLLVMOption.a",
        "libLLVMOrcJIT.a",
        "libLLVMOrcShared.a",
        "libLLVMOrcTargetProcess.a",
        "libLLVMPasses.a",
        "libLLVMPowerPCAsmParser.a",
        "libLLVMPowerPCCodeGen.a",
        "libLLVMPowerPCDesc.a",
        "libLLVMPowerPCDisassembler.a",
        "libLLVMPowerPCInfo.a",
        "libLLVMProfileData.a",
        "libLLVMRemarks.a",
        "libLLVMRISCVAsmParser.a",
        "libLLVMRISCVCodeGen.a",
        "libLLVMRISCVDesc.a",
        "libLLVMRISCVDisassembler.a",
        "libLLVMRISCVInfo.a",
        "libLLVMRISCVTargetMCA.a",
        "libLLVMRuntimeDyld.a",
        "libLLVMScalarOpts.a",
        "libLLVMSelectionDAG.a",
        "libLLVMSparcAsmParser.a",
        "libLLVMSparcCodeGen.a",
        "libLLVMSparcDesc.a",
        "libLLVMSparcDisassembler.a",
        "libLLVMSparcInfo.a",
        "libLLVMSupport.a",
        "libLLVMSymbolize.a",
        "libLLVMSystemZAsmParser.a",
        "libLLVMSystemZCodeGen.a",
        "libLLVMSystemZDesc.a",
        "libLLVMSystemZDisassembler.a",
        "libLLVMSystemZInfo.a",
        "libLLVMTableGen.a",
        "libLLVMTableGenCommon.a",
        "libLLVMTableGenGlobalISel.a",
        "libLLVMTarget.a",
        "libLLVMTargetParser.a",
        "libLLVMTextAPI.a",
        "libLLVMTransformUtils.a",
        "libLLVMVEAsmParser.a",
        "libLLVMVECodeGen.a",
        "libLLVMVectorize.a",
        "libLLVMVEDesc.a",
        "libLLVMVEDisassembler.a",
        "libLLVMVEInfo.a",
        "libLLVMWebAssemblyAsmParser.a",
        "libLLVMWebAssemblyCodeGen.a",
        "libLLVMWebAssemblyDesc.a",
        "libLLVMWebAssemblyDisassembler.a",
        "libLLVMWebAssemblyInfo.a",
        "libLLVMWebAssemblyUtils.a",
        "libLLVMWindowsDriver.a",
        "libLLVMWindowsManifest.a",
        "libLLVMX86AsmParser.a",
        "libLLVMX86CodeGen.a",
        "libLLVMX86Desc.a",
        "libLLVMX86Disassembler.a",
        "libLLVMX86Info.a",
        "libLLVMX86TargetMCA.a",
        "libLLVMXCoreCodeGen.a",
        "libLLVMXCoreDesc.a",
        "libLLVMXCoreDisassembler.a",
        "libLLVMXCoreInfo.a",
        "libLLVMXRay.a",
        //LLD
        "liblldCOFF.a",
        "liblldCommon.a",
        "liblldELF.a",
        "liblldMachO.a",
        "liblldMinGW.a",
        "liblldWasm.a",
        // Zlib
        "libz.a",
        // Zstd
        zstd,
        // Clang
        "libclangAnalysis.a",
        "libclangAnalysisFlowSensitive.a",
        "libclangAnalysisFlowSensitiveModels.a",
        "libclangAPINotes.a",
        "libclangARCMigrate.a",
        "libclangAST.a",
        "libclangASTMatchers.a",
        "libclangBasic.a",
        "libclangCodeGen.a",
        "libclangCrossTU.a",
        "libclangDependencyScanning.a",
        "libclangDirectoryWatcher.a",
        "libclangDriver.a",
        "libclangDynamicASTMatchers.a",
        "libclangEdit.a",
        "libclangExtractAPI.a",
        "libclangFormat.a",
        "libclangFrontend.a",
        "libclangFrontendTool.a",
        "libclangHandleCXX.a",
        "libclangHandleLLVM.a",
        "libclangIndex.a",
        "libclangIndexSerialization.a",
        "libclangInterpreter.a",
        "libclangLex.a",
        "libclangParse.a",
        "libclangRewrite.a",
        "libclangRewriteFrontend.a",
        "libclangSema.a",
        "libclangSerialization.a",
        "libclangStaticAnalyzerCheckers.a",
        "libclangStaticAnalyzerCore.a",
        "libclangStaticAnalyzerFrontend.a",
        "libclangSupport.a",
        "libclangTooling.a",
        "libclangToolingASTDiff.a",
        "libclangToolingCore.a",
        "libclangToolingInclusions.a",
        "libclangToolingInclusionsStdlib.a",
        "libclangToolingRefactoring.a",
        "libclangToolingSyntax.a",
        "libclangTransformer.a",
    };

    if (static or target.result.os.tag == .windows) {
        if (target.result.os.tag == .linux) compiler.linkage = .static;
        compiler.linkLibCpp();

        const prefix = "nat/cache";
        const llvm_version = "17.0.6";
        const llvm_path = b.option([]const u8, "llvm_path", "LLVM prefix path") orelse blk: {
            assert(!self_hosted_ci);
            if (third_party_ci or (!target.query.isNativeOs() or !target.query.isNativeCpu())) {
                var llvm_directory = try std.ArrayListUnmanaged(u8).initCapacity(b.allocator, 128);
                llvm_directory.appendSliceAssumeCapacity(prefix ++ "/");
                llvm_directory.appendSliceAssumeCapacity("llvm-");
                llvm_directory.appendSliceAssumeCapacity(llvm_version);
                llvm_directory.appendSliceAssumeCapacity("-");
                llvm_directory.appendSliceAssumeCapacity(@tagName(target.result.cpu.arch));
                llvm_directory.appendSliceAssumeCapacity("-");
                llvm_directory.appendSliceAssumeCapacity(@tagName(target.result.os.tag));
                llvm_directory.appendSliceAssumeCapacity("-");
                llvm_directory.appendSliceAssumeCapacity(@tagName(target.result.abi));
                llvm_directory.appendSliceAssumeCapacity("-");
                const cpu = if (std.mem.eql(u8, target.result.cpu.model.name, @tagName(target.result.cpu.arch))) "baseline" else target.result.cpu.model.name;
                llvm_directory.appendSliceAssumeCapacity(cpu);

                const url = try std.mem.concat(b.allocator, u8, &.{ "https://github.com/birth-software/fetch-llvm/releases/download/v", llvm_version, "/llvm-", llvm_version, "-", @tagName(target.result.cpu.arch), "-", @tagName(target.result.os.tag), "-", @tagName(target.result.abi), "-", cpu, ".tar.xz" });

                var dir = std.fs.cwd().openDir(llvm_directory.items, .{}) catch {
                    const run = b.addRunArtifact(fetcher);
                    compiler.step.dependOn(&run.step);
                    run.addArg("-prefix");
                    run.addArg(prefix);
                    run.addArg("-url");
                    run.addArg(url);
                    break :blk llvm_directory.items;
                };

                dir.close();

                break :blk llvm_directory.items;
            } else {
                break :blk switch (use_debug) {
                    true => "../llvm-17-static-debug",
                    false => "../llvm-17-static-release",
                };
            }
        };

        const llvm_include_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_path, "/include" });
        compiler.addIncludePath(std.Build.path(b, llvm_include_dir));
        const llvm_lib_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_path, "/lib" });

        for (static_llvm_libraries) |llvm_library| {
            compiler.addObjectFile(std.Build.path(b, try std.mem.concat(b.allocator, u8, &.{ llvm_lib_dir, "/", llvm_library })));
        }
    } else {
        compiler.linkSystemLibrary("LLVM-17");
        compiler.linkSystemLibrary("clang-cpp");
        compiler.linkSystemLibrary("lldCommon");
        compiler.linkSystemLibrary("lldCOFF");
        compiler.linkSystemLibrary("lldELF");
        compiler.linkSystemLibrary("lldMachO");
        compiler.linkSystemLibrary("lldWasm");
        compiler.linkSystemLibrary("unwind");
        compiler.linkSystemLibrary("zlib");
        compiler.linkSystemLibrary("zstd");

        switch (target.result.os.tag) {
            .linux => {
                compiler.addObjectFile(.{ .cwd_relative = "/usr/lib/gcc/x86_64-pc-linux-gnu/13.2.1/../../../../lib/libstdc++.so" });
                compiler.addIncludePath(.{ .cwd_relative = "/usr/include" });
                compiler.addIncludePath(.{ .cwd_relative = "/usr/include/c++/13.2.1" });
                compiler.addIncludePath(.{ .cwd_relative = "/usr/include/c++/13.2.1/x86_64-pc-linux-gnu" });
                compiler.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
            },
            .macos => {
                compiler.linkLibCpp();

                if (discover_brew_prefix(b, "llvm")) |llvm_prefix| {
                    const llvm_include_path = try std.mem.concat(b.allocator, u8, &.{ llvm_prefix, "/include" });
                    const llvm_lib_path = try std.mem.concat(b.allocator, u8, &.{ llvm_prefix, "/lib" });
                    compiler.addIncludePath(.{ .cwd_relative = llvm_include_path });
                    compiler.addLibraryPath(.{ .cwd_relative = llvm_lib_path });
                } else |err| {
                    return err;
                }

                if (discover_brew_prefix(b, "zstd")) |zstd_prefix| {
                    const zstd_lib_path = try std.mem.concat(b.allocator, u8, &.{ zstd_prefix, "/lib" });
                    compiler.addLibraryPath(.{ .cwd_relative = zstd_lib_path });
                } else |err| {
                    return err;
                }

                if (discover_brew_prefix(b, "zlib")) |zlib_prefix| {
                    const zlib_lib_path = try std.mem.concat(b.allocator, u8, &.{ zlib_prefix, "/lib" });
                    compiler.addLibraryPath(.{ .cwd_relative = zlib_lib_path });
                } else |err| {
                    return err;
                }
            },
            .windows => {},
            else => |tag| @panic(@tagName(tag)),
        }
    }

    if (target.result.os.tag == .windows) {
        compiler.linkSystemLibrary("ole32");
        compiler.linkSystemLibrary("version");
        compiler.linkSystemLibrary("uuid");
    }

    const install_exe = b.addInstallArtifact(compiler, .{});
    b.getInstallStep().dependOn(&install_exe.step);
    b.installDirectory(.{
        .source_dir = std.Build.path(b, "lib"),
        .install_dir = .bin,
        .install_subdir = "lib",
    });

    const compiler_exe_path = b.fmt("zig-out/bin/{s}", .{install_exe.dest_sub_path});
    const run_command = b.addSystemCommand(&.{compiler_exe_path});
    run_command.step.dependOn(b.getInstallStep());

    const debug_command = switch (os) {
        .linux => blk: {
            const result = b.addSystemCommand(&.{"gf2"});
            result.addArgs(&.{ "-ex", "set disassembly-flavor intel" });
            result.addArg("-ex=r");
            result.addArgs(&.{ "-ex", "up" });
            result.addArg("--args");
            break :blk result;
        },
        .windows => blk: {
            const result = b.addSystemCommand(&.{"remedybg"});
            result.addArg("-g");
            result.addArg(compiler_exe_path);

            break :blk result;
        },
        .macos => blk: {
            // not tested
            const result = b.addSystemCommand(&.{"lldb"});
            result.addArg("--");
            break :blk result;
        },
        else => @compileError("OS not supported"),
    };
    debug_command.step.dependOn(b.getInstallStep());
    debug_command.addArg(compiler_exe_path);

    const test_runner = b.addExecutable(.{
        .name = "test_runner",
        .root_source_file = .{ .path = "build/test_runner.zig" },
        .target = native_target,
        .optimize = optimization,
        .single_threaded = true,
    });
    b.default_step.dependOn(&test_runner.step);

    const test_command = b.addRunArtifact(test_runner);
    test_command.step.dependOn(&compiler.step);
    b.installArtifact(test_runner);
    test_command.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_command.addArgs(args);
        debug_command.addArgs(args);
        test_command.addArgs(args);
    }

    const run_step = b.step("run", "Test the Nativity compiler");
    run_step.dependOn(&run_command.step);
    const debug_step = b.step("debug", "Debug the Nativity compiler");
    debug_step.dependOn(&debug_command.step);
    const test_step = b.step("test", "Test the Nativity compiler");
    test_step.dependOn(&test_command.step);

    const test_all = b.step("test_all", "Test all");
    test_all.dependOn(&test_command.step);
}
