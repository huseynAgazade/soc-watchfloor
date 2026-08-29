"""Per-role authorization policy for the SOAR chat tools (splunk-soar-mcp).

The MCP server runs read-only and has no auth of its own; this policy is the
authorization boundary. It decides, per portal role, which tools the assistant
may use at all, and which tools touch tenant (customer-label) data so scope can
be enforced. Everything is fail-closed: a tool not listed for a role is not
offered to the model and is refused if somehow called.
"""
from __future__ import annotations

from ..rbac import Role

# --- tool groups (read-only set of the server) ---
DISCOVERY = {
    "soar_system_info", "soar_list_apps", "soar_list_app_actions", "soar_get_app_action",
    "soar_list_assets", "soar_get_asset", "soar_list_custom_functions", "soar_get_custom_function",
    "soar_list_repos", "soar_list_cef_fields", "soar_list_custom_fields",
}
METADATA = {"soar_list_container_statuses", "soar_list_severities"}
# container/customer data — tenant-scoped
CONTAINERS_LIST = {"soar_list_containers"}                    # takes a `label` filter
CONTAINERS_BYID = {"soar_get_container", "soar_list_artifacts", "soar_list_notes", "soar_list_comments"}
ARTIFACT_BYID = {"soar_get_artifact"}                         # artifact id -> parent not cheaply resolvable
CONTAINERS = CONTAINERS_LIST | CONTAINERS_BYID | ARTIFACT_BYID
PLAYBOOKS = {
    "soar_list_playbooks", "soar_get_playbook", "soar_list_playbook_blocks", "soar_get_playbook_source",
    "soar_list_playbook_runs", "soar_get_playbook_run", "soar_get_playbook_run_log",
    "soar_list_action_runs", "soar_get_action_run", "soar_list_workbooks", "soar_get_workbook",
}
VPE = {"soar_build_action_block", "soar_build_code_block", "soar_build_custom_function_block",
       "soar_build_decision_block", "soar_build_format_block", "soar_build_playbook_block",
       "soar_encode_vpe_block", "soar_decode_vpe_block"}
CUSTOM_LISTS = {"soar_list_custom_lists", "soar_get_custom_list"}
SYSTEM = {"soar_get_system_settings", "soar_get_license", "soar_get_system_health",
          "soar_list_cluster_nodes", "soar_list_feature_flags", "soar_list_ingestion_status"}
IDENTITY = {"soar_list_users", "soar_get_user", "soar_list_roles", "soar_get_role"}   # sensitive
RAW = {"soar_rest_get"}                                        # arbitrary GET — manager only

# --- role -> allowed tools ---
_base = DISCOVERY | METADATA | {"soar_system_info"}
ROLE_TOOLS: dict[Role, set[str]] = {
    Role.read_only:   CONTAINERS_LIST | CONTAINERS_BYID | METADATA | {"soar_system_info"},
    Role.l1_analyst:  CONTAINERS_LIST | CONTAINERS_BYID | METADATA | {"soar_system_info",
                      "soar_list_cef_fields", "soar_list_custom_fields"},
    Role.l2_analyst:  (CONTAINERS_LIST | CONTAINERS_BYID | METADATA | CUSTOM_LISTS |
                       {"soar_system_info", "soar_list_cef_fields", "soar_list_custom_fields",
                        "soar_list_action_runs", "soar_get_action_run"}),
    Role.shift_lead:  (CONTAINERS | METADATA | CUSTOM_LISTS | PLAYBOOKS | DISCOVERY |
                       {"soar_system_info"}),
    Role.soc_engineer:(CONTAINERS | METADATA | CUSTOM_LISTS | PLAYBOOKS | VPE | DISCOVERY |
                       {"soar_system_info"}),
    Role.soc_manager: (CONTAINERS | METADATA | CUSTOM_LISTS | PLAYBOOKS | VPE | DISCOVERY |
                       SYSTEM | IDENTITY | RAW | {"soar_system_info"}),
}

# tools whose access must be checked against the caller's tenant (customer) scope
LABEL_LIST_TOOLS = CONTAINERS_LIST          # require an in-scope `label`
CONTAINER_ID_TOOLS = CONTAINERS_BYID        # resolve the container's label, then check
SCOPE_UNRESOLVABLE = ARTIFACT_BYID          # only all-tenants callers may use these


def allowed_tools(role: Role) -> set[str]:
    return set(ROLE_TOOLS.get(role, set()))
