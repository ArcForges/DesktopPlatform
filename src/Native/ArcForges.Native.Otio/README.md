# ArcForges.Native.Otio

Source-generated bindings for the existing ABI preamble: version, dependency build information and
thread-local error queries. No media processing, image processing or timeline editing API is claimed.

Pin the exact package version centrally and commit package locks. Also reference `ArcForges.Native.Otio.Runtime.win-x64` at the same exact version and build/publish for `win-x64`. Call `OtioAbi.GetAbiVersion()`, `GetBuildInfo()` or `GetLastError()` in namespace `ArcForges.Native.Otio`.
The runtime package supplies app-local DLLs and a hash manifest. Loading never searches PATH or the
current working directory. Final product installation owns signing, read-only application paths and
any later hostile-content sandbox. Current native queries do not parse untrusted content.
