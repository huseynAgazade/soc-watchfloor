# mcp-roster

**Source:** portal database + SOAR list (monthly_shift_roster) + on-call rotation

Who is on shift, who was, distribution, horizon, coverage, absences, on-call.

## Tools
- `who_is_on_shift`
- `who_was_on_shift`
- `get_shift_distribution`
- `get_roster_horizon`
- `get_shift_coverage`
- `list_unassigned_shifts`
- `get_absences`
- `get_oncall`
- `get_person_schedule`
All read-only, tenant-scoped, returning small labelled result sets. See
`docs/ARCHITECTURE.md` §7.
