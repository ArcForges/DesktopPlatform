# Development conventions

Follow [AGENTS.md](../AGENTS.md), `.editorconfig` and the [contribution flow](../CONTRIBUTING.md).
Use exact centrally managed NuGet versions and committed per-project locks. Product consumers own their
SDK pin, global build files and package manifests; `ArcForges.Build.Policy` supplies portable policy only.
Never place product entities in shared Foundation or generate business wire contracts in this repository.
