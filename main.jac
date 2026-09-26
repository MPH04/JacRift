"""JacRift application entry. `jac start main.jac` serves the API and the UI."""

import from server {
    api_create_job,
    api_delete_job,
    api_get_events,
    api_get_findings,
    api_get_job,
    api_get_log,
    api_get_report,
    api_list_jobs,
    api_reproduce,
}
import from jrlib.http_facade { install_job_routes }

# Jaclang 0.16 does not dispatch @restspec paths. Install /api/jobs before
# the server builds its request handler. /function/api_* stays available.
with entry {
    install_job_routes();
}

cl {
    import ".styles.global.css";
    import from .components.console { Console }

    def:pub app -> JsxElement {
        return <Console />;
    }
}
