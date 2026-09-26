"""Investigation graph. Walkers cluster, trace ancestry, and collect evidence."""

node TargetNode {
    has target_id: str;
    has version: str;
}

node InputNode {
    has input_id: str;
    has parent_id: str;
    has mutation: str;
    has input_len: int;
    has input_hex: str;
}

node ExecNode {
    has exec_index: int;
    has exit_type: str;
    has sanitizer: str;
    has frame: str;
    has new_edges: int;
    has behavior_new: int;
    has fingerprint: str;
}

node Finding {
    has finding_id: str;
    has classification: str;
    has claim: str;
    has signature: str;
    has input_id: str;
    has reproducible: bool;
    has minimized: bool;
}

node HypothesisNode {
    has hyp_id: str;
    has text: str;
    has status: str;
    has reason: str;
    has narrow: bool;
}

node DecisionNode {
    has agent: str;
    has action: str;
    has detail: str;
}

edge MutatedFrom {}

edge ExecutedOn {}

edge Triggered {}

edge Supports {}

edge Contradicts {}

edge MinimizedTo {}

edge GeneratedBy {}

def reset_graph() {
    nodes = [n for n in [root -->]];
    for n in nodes {
        root del --> n;
        del n;
    }
}

walker ClusterWalk {
    has groups: dict;

    can start with Root entry {
        visit [-->];
    }

    can on_finding with Finding entry {
        sig = here.signature;
        if sig not in self.groups {
            self.groups[sig] = [];
        }
        self.groups[sig].append(here.finding_id);
    }
}

walker AncestryWalk {
    has chain: list;

    can step with InputNode entry {
        self.chain.append(here.input_id);
        visit [->:MutatedFrom:->];
    }
}

walker EvidenceWalk {
    has supported: int = 0;
    has contradicted: int = 0;

    can start with Root entry {
        visit [-->];
    }

    can on_finding with Finding entry {
        visit [-->];
    }

    can on_hyp with HypothesisNode entry {
        if here.status == "supported" {
            self.supported += 1;
        } elif here.status == "contradicted" {
            self.contradicted += 1;
        }
    }
}

def cluster_ids() -> dict {
    clustered = ClusterWalk(groups={});
    root spawn clustered;
    return clustered.groups;
}

def ancestry_of(start: InputNode) -> list {
    tracer = AncestryWalk(chain=[]);
    start spawn tracer;
    return tracer.chain;
}

def evidence_counts() -> dict {
    auditor = EvidenceWalk();
    root spawn auditor;
    return {"supported": auditor.supported, "contradicted": auditor.contradicted};
}

test "cluster walker groups signatures and ancestry follows mutations" {
    reset_graph();
    root ++> Finding(
        finding_id="f1", classification="CAPTURED", claim="c", signature="address|consume_length",
        input_id="aaaaaaaabbbbbbbb", reproducible=False, minimized=False
    );
    root ++> Finding(
        finding_id="f2", classification="CAPTURED", claim="c", signature="address|consume_length",
        input_id="bbbbbbbbcccccccc", reproducible=False, minimized=False
    );
    root ++> Finding(
        finding_id="f3", classification="NOVEL_BEHAVIOR", claim="n", signature="note|beta",
        input_id="cccccccccccccccc", reproducible=False, minimized=False
    );
    groups = cluster_ids();
    same = groups["address|consume_length"];
    assert same[0] == "f1";
    assert same[1] == "f2";
    assert groups["note|beta"][0] == "f3";
    parent = InputNode(input_id="parentparentparen", parent_id="", mutation="seed", input_len=2, input_hex="5652");
    child = InputNode(input_id="childchildchildch", parent_id="parentparentparen", mutation="bitflip", input_len=3, input_hex="56524c");
    root ++> parent;
    root ++> child;
    child +>: MutatedFrom() :+> parent;
    chain = ancestry_of(child);
    assert chain[0] == "childchildchildch";
    assert chain[1] == "parentparentparen";
    root ++> HypothesisNode(hyp_id="h1", text="length", status="supported", reason="frame", narrow=True);
    root ++> HypothesisNode(hyp_id="h2", text="rce", status="contradicted", reason="no pc", narrow=False);
    counts = evidence_counts();
    assert counts["supported"] == 1;
    assert counts["contradicted"] == 1;
    reset_graph();
}
