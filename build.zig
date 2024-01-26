const std = @import("std");
var all: bool = false;

pub fn build(b: *std.Build) !void {
    all = b.option(bool, "all", "All") orelse false;
    const optimization = b.standardOptimizeOption(.{});
    const llvm_debug = b.option(bool, "llvm_debug", "Use LLVM in the debug version") orelse false;
    const llvm_debug_path = b.option([]const u8, "llvm_debug_path", "LLVM debug path") orelse "../llvm-17-static-debug";
    const llvm_release_path = b.option([]const u8, "llvm_release_path", "LLVM release path") orelse "../llvm-17-static-release";
    const target_query = try std.zig.CrossTarget.parse(.{
        .arch_os_abi = "native-linux-musl",
    });
    const target = b.resolveTargetQuery(target_query);
    const exe = b.addExecutable(.{
        .name = "nat",
        .root_source_file = .{ .path = "bootstrap/main.zig" },
        .target = target,
        .optimize = optimization,
        .use_llvm = true,
        .use_lld = true,
    });
    exe.formatted_panics = false;
    exe.root_module.unwind_tables = false;
    exe.root_module.omit_frame_pointer = false;

    const llvm_dir = if (llvm_debug) llvm_debug_path else llvm_release_path;
    const llvm_include_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_dir, "/include" });
    const llvm_lib_dir = try std.mem.concat(b.allocator, u8, &.{ llvm_dir, "/lib" });

    exe.linkLibCpp();

    exe.addIncludePath(std.Build.LazyPath.relative(llvm_include_dir));
    exe.addCSourceFile(.{
        .file = std.Build.LazyPath.relative("bootstrap/backend/llvm.cpp"),
        .flags = &.{"-g"},
    });

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
        // Zlib
        "libz.a",
        "libzstd.a",
        //LLD
        "liblldCOFF.a",
        "liblldCommon.a",
        "liblldELF.a",
        "liblldMachO.a",
        "liblldMinGW.a",
        "liblldWasm.a",
    };

    inline for (llvm_libraries) |llvm_library| {
        exe.addObjectFile(std.Build.LazyPath.relative(try std.mem.concat(b.allocator, u8, &.{ llvm_lib_dir, "/", llvm_library })));
    }


    const install_exe = b.addInstallArtifact(exe, .{});
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

    if (b.args) |args| {
        run_command.addArgs(args);
        debug_command.addArgs(args);
    }

    const run_step = b.step("run", "Test the Nativity compiler");
    run_step.dependOn(&run_command.step);
    const debug_step = b.step("debug", "Debug the Nativity compiler");
    debug_step.dependOn(&debug_command.step);
}
