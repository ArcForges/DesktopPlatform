# ArcForges.ContentSandbox.Contracts

A thin facade over the generated `ArcForges.Contracts.LocalRpc.Sandbox` and `.Platform` bindings (CON.04, CON.05). It owns no authored or
generated wire type. It fixes what the parent and the helper must agree on beyond the schema: the contract-set digest of the launch, the
control methods, the profile limits of an invocation, the mapping of the generated slot grant, seal and acknowledgement records onto the
`ArcForges.LocalRpc` brokered-data records, and the one private launch frame the parent writes to the inherited standard input of the helper
(its closed resource inventory, identity, budget and the one-use bootstrap resource). This project is non-packable. Helper and broker
packaging, this facade included, is out of scope, not completed: PLT.46 was narrowed to the four Security packages (coordinator ruling
S52(1); P2-026 item 20), so no package of it exists or is claimed. The platform status of the helper (Windows, Linux, win-arm64; macOS is not
supported, P2-023) is in the helper README.
