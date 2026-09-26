"""Corpus index. Dedup by input id and keep a parent pointer for lineage."""

obj CorpusIndex {
    has items: dict;

    def add(input_id: str, parent_id: str, mutation: str, input_len: int, reason: str) -> bool {
        if input_id in self.items {
            return False;
        }
        self.items[input_id] = {
            "parent_id": parent_id,
            "mutation": mutation,
            "input_len": input_len,
            "reason": reason,
        };
        return True;
    }

    def lineage(input_id: str) -> list {
        chain = [];
        seen = {};
        current = input_id;
        while current != "" and current not in seen and current in self.items {
            seen[current] = True;
            chain.append({
                "input_id": current,
                "mutation": self.items[current]["mutation"],
                "parent_id": self.items[current]["parent_id"],
            });
            current = self.items[current]["parent_id"];
        }
        return chain;
    }
}

def fresh_corpus() -> CorpusIndex {
    return CorpusIndex(items={});
}

def retention_reason(new_edges: int, behavior_new: int, exit_type: str) -> str {
    reasons = [];
    if new_edges > 0 {
        reasons.append("new_edges");
    }
    if behavior_new > 0 {
        reasons.append("new_behavior");
    }
    if exit_type == "SANITIZER" or exit_type == "CRASH" or exit_type == "TIMEOUT" {
        reasons.append(exit_type.lower());
    }
    if len(reasons) == 0 {
        return "";
    }
    return "+".join(reasons);
}

test "lineage walks seed to child and duplicates are dropped" {
    corpus = fresh_corpus();
    assert corpus.add("seedseedseedseed", "", "seed", 2, "new_edges");
    assert not corpus.add("seedseedseedseed", "", "seed", 2, "new_edges");
    assert corpus.add("childchildchildch", "seedseedseedseed", "bitflip", 4, "sanitizer");
    chain = corpus.lineage("childchildchildch");
    assert len(chain) == 2;
    assert chain[0]["mutation"] == "bitflip";
    assert chain[1]["mutation"] == "seed";
    assert retention_reason(0, 0, "NORMAL") == "";
    assert retention_reason(2, 1, "SANITIZER") == "new_edges+new_behavior+sanitizer";
}
