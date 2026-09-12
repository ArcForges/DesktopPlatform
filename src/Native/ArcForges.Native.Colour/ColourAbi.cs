// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArcForges.Native.Abstractions;

[assembly: DisableRuntimeMarshalling]
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace ArcForges.Native.Colour;

public static unsafe partial class ColourAbi
{
    static ColourAbi() => NativeLoader.Register(typeof(ColourAbi).Assembly, "ArcSlateColorNative");

    public static NativeAbiVersion GetAbiVersion() => NativeAbi.GetVersion(GetVersionCore);

    public static string GetBuildInfo() => NativeAbi.GetBuildInfo(GetBuildInfoCore, GetErrorCore);

    public static NativeError GetLastError() => NativeAbi.GetError(GetErrorCore);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_abi_version")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetVersionCore(uint* major, uint* minor);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_build_info")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetBuildInfoCore(ref NativeBuffer output);

    [LibraryImport("ArcSlateColorNative", EntryPoint = "arc_color_get_last_error")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int GetErrorCore(ref NativeErrorBuffer output);
}
