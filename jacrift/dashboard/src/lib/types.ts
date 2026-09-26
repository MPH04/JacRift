export type Hypothesis = {
  status: string;
  text: string;
  reason: string;
  narrow?: boolean;
};

export type Finding = {
  finding_id: string;
  classification: string;
  claim: string;
  signature: string;
  input_id: string;
  parent_id?: string;
  mutation?: string;
  input_len?: number;
  input_hex?: string;
  exit_type?: string;
  sanitizer?: string;
  frame?: string;
  reproducible?: boolean;
  minimized?: boolean;
  minimized_len?: number;
  minimized_input_id?: string;
  minimized_hex?: string;
  error_class?: string;
  hypotheses?: Hypothesis[];
  replay_argv?: string[];
  new_edges?: number;
  behavior_new?: number;
};

export type SeriesPoint = {
  execs: number;
  edges: number;
  behavior_keys: number;
};

export type CampaignState = {
  schema?: string;
  generated_at?: string;
  campaign: {
    id?: string;
    target_id?: string;
    target_version?: string;
    status?: string;
    error?: string;
    seed?: number;
    compiler?: string;
    coverage?: string;
    flags?: string[];
    authorized_scope?: string;
  };
  metrics: {
    executions?: number;
    elapsed_ms?: number;
    execs_per_sec?: number;
    corpus_size?: number;
    instrumented_edges?: number;
    edges_hit?: number;
    behavior_keys?: number;
    behavior_keys_engine?: number;
    behavior_disagreements?: number;
    sanitizer_failures?: number;
    crashes?: number;
    timeouts?: number;
  };
  series?: SeriesPoint[];
  findings?: Finding[];
  agents?: { agent: string; action: string; detail: string }[];
  experiments?: {
    id: string;
    hypothesis?: string;
    expected?: string;
    observed?: string;
    interpretation?: string;
    confidence?: string;
  }[];
  corpus?: {
    input_id: string;
    parent_id?: string;
    mutation?: string;
    input_len?: number;
    reason?: string;
    lineage?: { input_id: string; mutation: string }[];
  }[];
  limitations?: string[];
  checks?: Record<string, boolean>;
  graph?: {
    nodes: { id: string; type: string; label: string }[];
    edges: { source: string; target: string; type: string }[];
  };
};

export const EMPTY_STATE: CampaignState = {
  campaign: { status: "idle", target_id: "riftpacket", target_version: "demo-1" },
  metrics: {},
  findings: [],
  series: [],
  agents: [],
  experiments: [],
  limitations: [],
  checks: {},
};
