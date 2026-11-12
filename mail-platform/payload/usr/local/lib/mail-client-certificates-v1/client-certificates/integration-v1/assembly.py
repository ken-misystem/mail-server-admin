"""Reviewed integration assembly/metadata planning, inert until explicitly used."""
from compat import require
from connector import Endpoint, RoleConnector
from database import components
from grants import inspect_view, render, validate_snapshot


def grant_plan(manifest, metadata_cursor, full_privilege_snapshot):
    """Provisioning audit connection only. Return SQL, never execute it.

    This is an audit of an already prepared candidate: a fresh, ungranted schema
    cannot pass the effective-grant snapshot gate. Initial deployment requires
    a separate staged plan and explicit approval; this function is not an apply.
    """
    scope = inspect_view(metadata_cursor, manifest)
    validate_snapshot(full_privilege_snapshot)
    return {'sql':render(manifest,scope),'fixed_columns':list(scope.columns),
            'requires_live_metadata_provenance':True,'production_apply_authorized':False}


def assemble(manifest, socket, config_fds, runtime, session_port, owner_provider):
    # Principal validation is shared with the proven old planner; no view metadata
    # or GRANT is queried/executed by normal runtime component assembly.
    from compat import old_privileges
    old_privileges.render(manifest)
    require(type(config_fds) is dict and set(config_fds) == {'identity_reader','orchestrator','gateway_reader'}
            and all(type(v) is int and v >= 0 for v in config_fds.values())
            and len(set(config_fds.values())) == 3, 'distinct_role_fds', 'assembly')
    factories = {role:RoleConnector(fd,runtime,Endpoint(socket,manifest[role],'mail_management'))
                 for role,fd in config_fds.items()}
    return components(factories['identity_reader'],factories['orchestrator'],factories['gateway_reader'],
                      session_port,owner_provider)

