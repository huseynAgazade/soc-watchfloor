# mcp-detection

**Source:** detection-attck-mapper pipeline (Splunk + Falcon EDR export)

ATT&CK coverage (top-level), rule inventory, phantom cells, unmapped/operational/test rules.

## Tools
- `get_mitre_coverage`
- `list_coverage_gaps`
- `list_rules`
- `get_rule_detail`
- `list_unmapped_rules`
- `list_disabled_rules`
- `get_phantom_cells`
- `compare_tenant_coverage`
All read-only, tenant-scoped, returning small labelled result sets. See
`docs/ARCHITECTURE.md` §7.
