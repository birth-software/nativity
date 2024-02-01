const std = @import("std");
const assert = std.debug.assert;

pub fn build(b: *std.Build) !void {
    const self_hosted_ci = b.option(bool, "self_hosted_ci", "This option enables the self-hosted CI behavior") orelse false;
    const third_party_ci = b.option(bool, "third_party_ci", "This option enables the third-party CI behavior") orelse false;
    const is_ci = self_hosted_ci or third_party_ci;
    const native_target = b.resolveTargetQuery(.{});
    const optimization = b.standardOptimizeOption(.{});
    var target_query = b.standardTargetOptionsQueryOnly(.{});
    const os = target_query.os_tag orelse @import("builtin").os.tag;
    if (os == .linux) {
        target_query.abi = .musl;
    }
    const target = b.resolveTargetQuery(target_query);
    const llvm_version = "17.0.6";
    var fetcher_run: ?*std.Build.Step.Run = null;
    const llvm_path = b.option([]const u8, "llvm_path", "LLVM prefix path") orelse blk: {
        assert(!self_hosted_ci);
        if (third_party_ci or (!target.query.isNativeOs() or !target.query.isNativeCpu())) {
            const prefix = "nat/cache";
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
            llvm_directory.appendSliceAssumeCapacity(if (std.mem.eql(u8, target.result.cpu.model.name, @tagName(target.result.cpu.arch))) "baseline" else target.result.cpu.model.name);

            var dir = std.fs.cwd().openDir(llvm_directory.items, .{}) catch {
                const llvm_fetcher = b.addExecutable(.{
                    .name = "llvm_fetcher",
                    .root_source_file = .{ .path = "build/llvm_fetcher.zig" },
                    .target = native_target,
                    .optimize = .ReleaseFast,
                    .single_threaded = true,
                });
                const run = b.addRunArtifact(llvm_fetcher);
                fetcher_run = run;
                run.addArg("-prefix");
                run.addArg(prefix);
                run.addArg("-version");
                run.addArg(llvm_version);
                run.addArg("-arch");
                run.addArg(@tagName(target.result.cpu.arch));
                run.addArg("-os");
                run.addArg(@tagName(target.result.os.tag));
                run.addArg("-abi");
                run.addArg(@tagName(target.result.abi));
                run.addArg("-cpu");
                run.addArg(target.result.cpu.model.name);
                break :blk llvm_directory.items;
            };

            dir.close();

            break :blk llvm_directory.items;
        } else {
            const use_debug = b.option(bool, "use_debug", "This option enables the LLVM debug build in the development PC") orelse false;
            break :blk switch (use_debug) {
                true => "../llvm-17-static-debug",
                false => "../llvm-17-static-release",
            };
        }
    };

    const compiler = b.addExecutable(.{
        .name = "nat",
        .root_source_file = .{ .path = "bootstrap/main.zig" },
        .target = target,
        .optimize = optimization,
    });
    compiler.formatted_panics = is_ci;
    compiler.root_module.unwind_tables = is_ci;
    compiler.root_module.omit_frame_pointer = false;
    compiler.want_lto = false;

    compiler.linkLibC();
    compiler.linkSystemLibrary("c++");

    if (target.result.os.tag == .windows) {
        compiler.linkSystemLibrary("ole32");
        compiler.linkSystemLibrary("version");
        compiler.linkSystemLibrary("uuid");
        compiler.linkSystemLibrary("msvcrt-os");
    }

    if (fetcher_run) |fr| {
        compiler.step.dependOn(&fr.step);
    }

    const llvm_include_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_path, "/include" });
    const llvm_lib_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_path, "/lib" });
    compiler.addIncludePath(std.Build.LazyPath.relative(llvm_include_dir));
    const cpp_files = .{
        "bootstrap/backend/llvm.cpp",
        "bootstrap/frontend/clang/main.cpp",
        "bootstrap/frontend/clang/cc1.cpp",
        "bootstrap/frontend/clang/cc1as.cpp",
    };
    compiler.addCSourceFiles(.{
        .files = &cpp_files,
        .flags = &.{"-g"},
    });

    const zlib = if (target.result.os.tag == .windows) "zstd.lib" else "libzstd.a";
    const llvm_libraries = [_][]const u8{
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
        zlib,
        "libz.a",
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

    for (llvm_libraries) |llvm_library| {
        compiler.addObjectFile(std.Build.LazyPath.relative(try std.mem.concat(b.allocator, u8, &.{ llvm_lib_dir, "/", llvm_library })));
    }

    const install_exe = b.addInstallArtifact(compiler, .{});
    b.getInstallStep().dependOn(&install_exe.step);
    b.installDirectory(.{
        .source_dir = std.Build.LazyPath.relative("lib"),
        .install_dir = .bin,
        .install_subdir = "lib",
    });

    const compiler_exe_path = b.fmt("zig-out/bin/{s}", .{install_exe.dest_sub_path});
    const run_command = b.addSystemCommand(&.{compiler_exe_path});
    run_command.step.dependOn(b.getInstallStep());

    const debug_command = switch (@import("builtin").os.tag) {
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
            result.addArg(compiler_exe_path);
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

    const test_command = b.addRunArtifact(test_runner);
    test_command.step.dependOn(&compiler.step);
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
}
