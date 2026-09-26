"""JacRift HTTP API. Investigation stays in jac/. This module is the server edge.

`jac start` is launched from the repository root, which is on Python's import path,
so `jrlib` resolves without mutating sys.path at module scope.

These functions are the native Jac surface: POST /function/<name>. The product
paths POST/GET/DELETE /api/jobs are installed by jrlib.http_facade because
jaclang 0.16 does not route @restspec path metadata.
"""

import from jrlib.api {
    create_job,
    delete_job,
    get_events,
    get_findings,
    get_job,
    get_log,
    get_report,
    list_jobs,
    reproduce,
}
import from http { HTTPMethod }

@restspec(method=HTTPMethod.POST, path="/api/jobs")
def:pub api_create_job(repository_url: str, authorization_confirmed: bool, scope: str) -> dict {
    return create_job(repository_url, authorization_confirmed, scope, True) as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs")
def:pub api_list_jobs() -> dict {
    return list_jobs() as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs/{job_id}")
def:pub api_get_job(job_id: str) -> dict {
    return get_job(job_id) as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs/{job_id}/log")
def:pub api_get_log(job_id: str) -> dict {
    return get_log(job_id) as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs/{job_id}/events")
def:pub api_get_events(job_id: str) -> dict {
    return get_events(job_id) as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs/{job_id}/findings")
def:pub api_get_findings(job_id: str) -> dict {
    return get_findings(job_id) as dict;
}

@restspec(method=HTTPMethod.GET, path="/api/jobs/{job_id}/report")
def:pub api_get_report(job_id: str) -> dict {
    return get_report(job_id) as dict;
}

@restspec(method=HTTPMethod.POST, path="/api/jobs/{job_id}/reproduce")
def:pub api_reproduce(job_id: str, finding_id: str) -> dict {
    return reproduce(job_id, finding_id) as dict;
}

@restspec(method=HTTPMethod.DELETE, path="/api/jobs/{job_id}")
def:pub api_delete_job(job_id: str) -> dict {
    return delete_job(job_id) as dict;
}
