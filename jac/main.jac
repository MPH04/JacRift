"""VectorRift entry. `jac run main.jac -- campaign --execs 400 --seed 1`."""

import sys;

import from campaign { run_cli }

with entry:__main__ {
    code = run_cli(sys.argv);
    sys.exit(code);
}
