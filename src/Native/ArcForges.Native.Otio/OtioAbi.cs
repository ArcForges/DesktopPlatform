// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

[assembly: DisableRuntimeMarshalling]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ArcForges.Native.Otio;

public static unsafe partial class OtioAbi
{
    static OtioAbi() => NativeLoader.Register(typeof(OtioAbi).Assembly, "ArcSlateOtioNative");

    public static NativeAbiVersion GetAbiVersion() => NativeAbi.GetVersion(GetVersionCore);

    public static string GetBuildInfo() => NativeAbi.GetBuildInfo(GetBuildInfoCore, GetErrorCore);

    public static NativeError GetLastError() => NativeAbi.GetError(GetErrorCore);

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetVersionCore(uint* major, uint* minor);

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetBuildInfoCore(ref NativeBuffer output);

    [LibraryImport("ArcSlateOtioNative", EntryPoint = "arc_otio_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetErrorCore(ref NativeErrorBuffer output);
}
