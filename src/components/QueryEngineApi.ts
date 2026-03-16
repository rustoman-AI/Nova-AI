import { invoke } from '@tauri-apps/api/core';

export interface ExploitationPathPayload {
    entry_point: string;
    target_component: string;
    vulnerability_id: string;
    proof_chain: string[];
}

export interface CopyleftRiskPayload {
    source_component: string;
    license: string;
    affected_component: string;
}

export interface TrustDecayPayload {
    component: string;
    reason: string;
    downstream_count: number;
}

export interface BlastRadiusPayload {
    vulnerability_id: string;
    vulnerable_component: string;
    affected_components: string[];
    total_affected: number;
}

export interface DatalogStats {
    total_facts: number;
    total_derived: number;
    components_analyzed: number;
    vulnerabilities_analyzed: number;
    entry_points_analyzed: number;
}

export interface DatalogResult {
    exploitation_paths: ExploitationPathPayload[];
    copyleft_risks: CopyleftRiskPayload[];
    trust_decay: TrustDecayPayload[];
    blast_radius: BlastRadiusPayload[];
    stats: DatalogStats;
}

export interface SecQlPathResult {
    nodes: string[];
}

export const QueryEngineAPI = {
    async computeAttackPaths(sbomJson?: string, astRoot?: string): Promise<DatalogResult> {
        return await invoke('compute_attack_paths', {
            sbomJson: sbomJson || null,
            astRoot: astRoot || null,
        });
    },

    async executeSecqlQuery(query: string, rootDir: string, sbomPath?: string): Promise<SecQlPathResult[]> {
        return await invoke('execute_secql_query', {
            rootDir,
            sbomPath: sbomPath || null,
            query,
        });
    }
};
