import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from correlate import vuln_score, iam_score, risk_level, best_first_action


def test_vuln_score_zero_when_no_findings():
    assert vuln_score(0, 0) == 0


def test_vuln_score_caps_at_100():
    assert vuln_score(critical=100, high=100) == 100


def test_vuln_score_weights_critical_more_than_high():
    critical_only = vuln_score(critical=1, high=0)
    high_only = vuln_score(critical=0, high=1)
    assert critical_only > high_only


def test_iam_score_wildcard_is_max():
    role = {"has_wildcard": True, "all_actions": ["s3:*"]}
    assert iam_score(role) == 100


def test_iam_score_no_wildcard_is_capped_at_50():
    role = {"has_wildcard": False, "all_actions": ["s3:GetObject"] * 50}
    assert iam_score(role) == 50


def test_iam_score_scales_with_action_count():
    small_role = {"has_wildcard": False, "all_actions": ["s3:GetObject"]}
    bigger_role = {"has_wildcard": False, "all_actions": ["s3:GetObject", "s3:ListBucket"]}
    assert iam_score(bigger_role) > iam_score(small_role)


def test_risk_level_boundaries():
    assert risk_level(0) == "LOW"
    assert risk_level(14) == "LOW"
    assert risk_level(15) == "MEDIUM"
    assert risk_level(39) == "MEDIUM"
    assert risk_level(40) == "HIGH"
    assert risk_level(69) == "HIGH"
    assert risk_level(70) == "CRITICAL"
    assert risk_level(100) == "CRITICAL"


def test_best_first_action_prefers_the_lower_scenario():
    scenarios = {"current": 89, "after_image_update": 10, "after_iam_fix": 22, "after_both": 2}
    assert best_first_action(scenarios) == "Update the image first"


def test_best_first_action_when_only_iam_helps():
    scenarios = {"current": 22, "after_image_update": 22, "after_iam_fix": 2, "after_both": 2}
    assert best_first_action(scenarios) == "Fix IAM permissions first"


def test_best_first_action_when_nothing_helps():
    scenarios = {"current": 10, "after_image_update": 10, "after_iam_fix": 10, "after_both": 10}
    assert best_first_action(scenarios) == "No single action reduces the score"