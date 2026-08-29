# mcp-splunk

**Source:** Splunk SIEM (editable SPL from the admin query catalog)

Curated SIEM metrics — case volume, EPS by feed, notable trend, noisy rules — via tokenized read-only SPL.

## Tools
- `list_dashboards`
- `query_metric`
- `get_soc_metric_pack`
- `compare_periods`
All read-only, tenant-scoped, returning small labelled result sets. See
`docs/ARCHITECTURE.md` §7.
