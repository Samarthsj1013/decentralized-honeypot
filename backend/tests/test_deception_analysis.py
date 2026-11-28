import json

from app.experiments.analysis import analyze_paired_comparison


def test_paired_analysis_requires_complete_unique_run_grid_and_reports_cluster_intervals(tmp_path):
    scenarios = ["reconnaissance", "multi_port_probing"]
    rows = []
    for scenario_index, scenario in enumerate(scenarios):
        for mode, engaged, tp in (("baseline", False, 1), ("adaptive", True, 2), ("closed_loop", False, 2)):
            rows.append({
                "scenario": scenario,
                "repetition": 1,
                "mode": mode,
                "completed": True,
                "simulated_attacker_engaged": engaged,
                "true_positives": tp + scenario_index,
                "suspicious_events": 4,
            })
    source = tmp_path / "input.json"
    source.write_text(json.dumps({
        "experiment_id": "fixture",
        "scenarios": scenarios,
        "repetitions": 1,
        "modes": ["baseline", "adaptive", "closed_loop"],
        "scenario_results": rows,
    }), encoding="utf-8")

    result = analyze_paired_comparison(source, bootstrap_samples=200, seed=7)

    paired = result["comparisons"]["engagement"]["baseline_to_adaptive"]
    assert paired["paired_run_count"] == 2
    assert paired["mean_paired_delta"] == 1.0
    assert len(paired["scenario_cluster_bootstrap_95_ci"]) == 2
    assert paired["scenario_cluster_bootstrap_95_ci"] == [1.0, 1.0]


def test_paired_analysis_rejects_missing_or_incomplete_runs(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps({
        "experiment_id": "incomplete",
        "scenarios": ["reconnaissance"],
        "repetitions": 1,
        "modes": ["baseline", "adaptive"],
        "scenario_results": [],
    }), encoding="utf-8")

    import pytest

    with pytest.raises(ValueError, match="exactly one unique row"):
        analyze_paired_comparison(source, bootstrap_samples=100)
