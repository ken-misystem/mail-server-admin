"""Durable publication orchestration. Adapters are fixed deployment code, never HTTP inputs."""


def publish_one(store, adapter, kind):
    # The persisted claim survives process death. A restart cannot repeat it.
    desired, credential = store.begin_apply(kind)
    revision = desired["revision"]
    journal = None
    reload_attempted = False
    try:
        adapter.preflight(kind, desired, credential)
        journal = adapter.prepare(kind, desired, credential)
        adapter.install(journal)
        adapter.validate(kind)
        reload_attempted = True
        adapter.reload(kind)
        adapter.verify_effective(kind, desired)
    except Exception as failure:
        # Only finite exception classes leave the private diagnostic channel.
        capture_errors = []
        try:
            adapter.capture_failure(kind, revision, failure)
        except Exception as diagnostic:
            capture_errors.append(type(diagnostic).__name__)
        restored = False
        try:
            if journal is None:
                restored = True
            else:
                adapter.restore_known(journal)
                adapter.validate_restored(kind)
                if reload_attempted:
                    adapter.reload(kind)
                adapter.verify_restored(kind)
                restored = True
        except Exception as recovery:
            try:
                adapter.capture_failure(kind, revision, recovery)
            except Exception as diagnostic:
                capture_errors.append(type(diagnostic).__name__)
        store.finish_apply(kind, revision, applied=False, restored=restored)
        return {"kind": kind, "revision": revision, "state": "failed" if restored else "unknown",
                "diagnostic_record_errors": capture_errors}
    # A lost acknowledgement here is not a reason to restore already-live settings.
    # The next operator must reconcile the persisted applying intent.
    store.finish_apply(kind, revision, applied=True, restored=False)
    return {"kind": kind, "revision": revision, "state": "applied"}
