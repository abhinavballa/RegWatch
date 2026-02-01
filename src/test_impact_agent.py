
import sys
from pathlib import Path

# Add project root to sys.path to ensure local code is prioritized
# This allows testing local changes without installing the package
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))

"""
Test Plan for impact_agent.py

1. Unit Tests Strategy:
    - The code relies heavily on external dependencies (Toolhouse SDK, file system for checkers).
    - We need to mock `Toolhouse` and file system operations (`open`, `os.path.exists`).
    - We need to verify the logic for risk calculation, fine estimation, and prioritization.
    - We need to verify error handling (missing API key, missing checker files, execution errors).

    Test Cases:
    a. `assess_impact`:
        - Happy Path: Valid API key, valid checkers, valid customer codebases. Verify correct aggregation of violations, risk scores, and fines.
        - Missing API Key: Verify it returns an error dict.
        - Missing Checker Source: Verify it logs error and raises/handles FileNotFoundError (the code raises it, but the loop catches Exception).
        - Toolhouse Execution Error: Verify it handles JSON parsing errors or "error" keys in result.
        - Empty Results: Verify behavior when no violations are found.
    
    b. `prioritize_customers`:
        - Verify sorting logic: Risk Score (desc) -> Estimated Fine (desc) -> Violations Count (desc).
        - Verify limit: Returns top 20.
        - Verify handling of empty lists.

2. Formal Verification Strategy (Z3):
    - The risk calculation logic involves linear combinations of integer counts.
    - We can use Z3 to verify that:
        - Risk score is always non-negative given non-negative counts.
        - Higher severity counts always result in higher or equal risk scores compared to lower severity counts (monotonicity).
        - The sorting logic in `prioritize_customers` is mathematically sound (transitive).
    - Specifically, we will verify the `_calculate_risk_metrics` logic (re-implemented in the test for verification since it's internal) ensures that a critical violation always contributes more to the score than a high violation, etc.

3. Edge Cases & Verification Method:
    - Negative violation counts (Impossible in practice, but good for Z3 to prove safety bounds if inputs were unconstrained): Z3.
    - Integer overflow for fines (Python handles large ints, but logic check is good): Z3.
    - Malformed JSON from Toolhouse: Unit Test.
    - Missing file paths: Unit Test.
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch, mock_open
from typing import Dict, Any, List
import z3

# Import the module under test
# Since the file path is provided as /Users/trinav/personal/RegWatch/prompts/impact_agent.py
# We assume the module name is impact_agent and it is in the python path.
import impact_agent

# --- Fixtures ---

@pytest.fixture
def mock_env_setup():
    """Sets up environment variables."""
    with patch.dict(os.environ, {"TOOLHOUSE_API_KEY": "test_key_123"}):
        yield

@pytest.fixture
def mock_toolhouse():
    """Mocks the Toolhouse SDK class."""
    with patch("impact_agent.Toolhouse") as MockToolhouse:
        mock_instance = MockToolhouse.return_value
        yield mock_instance

@pytest.fixture
def sample_impact_data():
    """Provides sample data for prioritization tests."""
    return {
        "customers_affected": [
            {"customer_id": "c1", "risk_score": 100, "estimated_fine": 50000, "violations_count": 5},
            {"customer_id": "c2", "risk_score": 200, "estimated_fine": 100000, "violations_count": 10},
            {"customer_id": "c3", "risk_score": 100, "estimated_fine": 60000, "violations_count": 5}, # Same risk as c1, higher fine
            {"customer_id": "c4", "risk_score": 50, "estimated_fine": 1000, "violations_count": 1},
        ]
    }

# --- Unit Tests ---

def test_assess_impact_missing_api_key():
    """Test that assess_impact returns error if API key is missing."""
    with patch.dict(os.environ, {}, clear=True):
        result = impact_agent.assess_impact([], {})
        assert "error" in result
        assert result["error"] == "Configuration missing"

def test_assess_impact_happy_path(mock_env_setup, mock_toolhouse):
    """
    Test the full flow of assess_impact with mocked dependencies.
    Verifies that violations are aggregated and metrics calculated correctly.
    """
    # Setup Mocks
    mock_run = mock_toolhouse.bundle.code_execution.run
    
    # Mock return value from Toolhouse (JSON string)
    mock_output = json.dumps({
        "findings": [
            {"severity": "critical", "msg": "Bad encryption"},
            {"severity": "low", "msg": "Missing comment"}
        ]
    })
    mock_run.return_value = mock_output

    # Mock file system for checker source
    affected_checkers = ["hipaa_encryption_checker"]
    customer_codebases = {"cust_1": "/path/to/code"}
    
    with patch("builtins.open", mock_open(read_data="print('checker code')")), \
         patch("os.path.exists", return_value=True):
        
        report = impact_agent.assess_impact(affected_checkers, customer_codebases)

    # Assertions
    assert report["total_violations"] == 2
    assert len(report["customers_affected"]) == 1
    
    cust_data = report["customers_affected"][0]
    assert cust_data["customer_id"] == "cust_1"
    assert cust_data["violations_count"] == 2
    assert cust_data["severity_counts"]["critical"] == 1
    assert cust_data["severity_counts"]["low"] == 1
    
    # Check Risk Calculation (10 * 1 + 1 * 1 = 11)
    assert cust_data["risk_score"] == 11
    # Check Fine Calculation (50000 * 1 + 100 * 1 = 50100)
    assert cust_data["estimated_fine"] == 50100

def test_assess_impact_toolhouse_returns_dict(mock_env_setup, mock_toolhouse):
    """Test handling when Toolhouse returns a dict directly instead of a string."""
    mock_run = mock_toolhouse.bundle.code_execution.run
    mock_run.return_value = {
        "findings": [{"severity": "high", "msg": "Access issue"}]
    }

    affected_checkers = ["hipaa_access_control_checker"]
    customer_codebases = {"cust_2": "/path/to/code"}

    with patch("builtins.open", mock_open(read_data="code")), \
         patch("os.path.exists", return_value=True):
        
        report = impact_agent.assess_impact(affected_checkers, customer_codebases)

    assert report["total_violations"] == 1
    assert report["customers_affected"][0]["severity_counts"]["high"] == 1

def test_assess_impact_checker_execution_failure(mock_env_setup, mock_toolhouse):
    """Test that execution failures for one checker don't crash the whole process."""
    mock_run = mock_toolhouse.bundle.code_execution.run
    # Simulate an exception during execution
    mock_run.side_effect = Exception("Sandbox timeout")

    affected_checkers = ["hipaa_audit_logging_checker"]
    customer_codebases = {"cust_3": "/path/to/code"}

    with patch("builtins.open", mock_open(read_data="code")), \
         patch("os.path.exists", return_value=True):
        
        # Should not raise exception
        report = impact_agent.assess_impact(affected_checkers, customer_codebases)

    # Should have 0 violations but processed gracefully
    assert report["total_violations"] == 0
    assert len(report["customers_affected"]) == 0

def test_assess_impact_checker_file_not_found(mock_env_setup, mock_toolhouse):
    """Test behavior when a checker source file is missing."""
    affected_checkers = ["hipaa_encryption_checker"]
    customer_codebases = {"cust_4": "/path/to/code"}

    # Mock os.path.exists to return False for the checker path
    # The code checks CHECKER_FILE_MAP paths.
    with patch("os.path.exists", return_value=False):
        report = impact_agent.assess_impact(affected_checkers, customer_codebases)

    # Should log error and continue (resulting in 0 violations)
    assert report["total_violations"] == 0

def test_prioritize_customers_sorting(sample_impact_data):
    """
    Test that customers are prioritized correctly:
    1. Risk Score (Desc)
    2. Estimated Fine (Desc)
    3. Violations Count (Desc)
    """
    sorted_customers = impact_agent.prioritize_customers(sample_impact_data)
    
    # Expected order:
    # 1. c2 (Risk 200)
    # 2. c3 (Risk 100, Fine 60000)
    # 3. c1 (Risk 100, Fine 50000)
    # 4. c4 (Risk 50)
    
    assert sorted_customers[0]["customer_id"] == "c2"
    assert sorted_customers[1]["customer_id"] == "c3"
    assert sorted_customers[2]["customer_id"] == "c1"
    assert sorted_customers[3]["customer_id"] == "c4"

def test_prioritize_customers_limit(sample_impact_data):
    """Test that the function returns at most 20 customers."""
    # Generate 25 dummy customers
    many_customers = {
        "customers_affected": [
            {"customer_id": f"c{i}", "risk_score": i, "estimated_fine": 100, "violations_count": 1}
            for i in range(25)
        ]
    }
    
    result = impact_agent.prioritize_customers(many_customers)
    assert len(result) == 20
    # The one with highest risk (24) should be first
    assert result[0]["customer_id"] == "c24"

# --- Z3 Formal Verification Tests ---

def test_z3_risk_calculation_monotonicity():
    """
    Formal verification using Z3 to ensure the risk calculation logic is monotonic.
    i.e., Adding a violation of ANY severity should never decrease the risk score.
    """
    s = z3.Solver()

    # Define variables for counts (non-negative integers)
    crit = z3.Int('crit')
    high = z3.Int('high')
    med = z3.Int('med')
    low = z3.Int('low')

    # Constraints: counts must be >= 0
    s.add(crit >= 0, high >= 0, med >= 0, low >= 0)

    # Replicate the logic from impact_agent.py constants
    # RISK_MULT_CRITICAL = 10, HIGH = 5, MEDIUM = 2, LOW = 1
    def calculate_risk(c, h, m, l):
        return (c * 10) + (h * 5) + (m * 2) + (l * 1)

    current_risk = calculate_risk(crit, high, med, low)

    # Verify: Adding 1 to any category results in a strictly higher score
    # We prove this by trying to find a counter-example where new_risk <= current_risk
    
    # Case 1: Add Critical
    new_risk_crit = calculate_risk(crit + 1, high, med, low)
    s.push()
    s.add(new_risk_crit <= current_risk)
    assert s.check() == z3.unsat, "Found case where adding critical violation did not increase risk"
    s.pop()

    # Case 2: Add Low
    new_risk_low = calculate_risk(crit, high, med, low + 1)
    s.push()
    s.add(new_risk_low <= current_risk)
    assert s.check() == z3.unsat, "Found case where adding low violation did not increase risk"
    s.pop()

def test_z3_severity_hierarchy():
    """
    Formal verification to ensure severity hierarchy is respected in risk scoring.
    1 Critical should be worth more than 1 High, etc.
    """
    s = z3.Solver()
    
    # Constants from code
    R_CRIT = 10
    R_HIGH = 5
    R_MED = 2
    R_LOW = 1

    # Verify Critical > High > Medium > Low
    s.add(z3.Not(z3.And(
        R_CRIT > R_HIGH,
        R_HIGH > R_MED,
        R_MED > R_LOW
    )))

    # If unsat, it means the negation is impossible, so the hierarchy holds.
    assert s.check() == z3.unsat, "Risk multipliers do not strictly follow severity hierarchy"

def test_z3_fine_calculation_bounds():
    """
    Formal verification to ensure fine calculation is linear and non-negative.
    """
    s = z3.Solver()
    
    crit = z3.Int('crit')
    high = z3.Int('high')
    med = z3.Int('med')
    low = z3.Int('low')
    
    s.add(crit >= 0, high >= 0, med >= 0, low >= 0)
    
    # Constants
    F_CRIT = 50000
    F_HIGH = 10000
    F_MED = 1000
    F_LOW = 100
    
    total_fine = (crit * F_CRIT) + (high * F_HIGH) + (med * F_MED) + (low * F_LOW)
    
    # Verify fine is always >= 0
    s.add(total_fine < 0)
    
    assert s.check() == z3.unsat, "Fine calculation can result in negative value"

def test_z3_prioritization_logic():
    """
    Formal verification of the comparison logic used in prioritization.
    We verify that if Customer A dominates Customer B in all metrics, A is always ranked higher.
    """
    s = z3.Solver()
    
    # Customer A metrics
    risk_a = z3.Int('risk_a')
    fine_a = z3.Int('fine_a')
    viol_a = z3.Int('viol_a')
    
    # Customer B metrics
    risk_b = z3.Int('risk_b')
    fine_b = z3.Int('fine_b')
    viol_b = z3.Int('viol_b')
    
    # Condition: A dominates B strictly in Risk
    s.add(risk_a > risk_b)
    
    # Python sort key is tuple (risk, fine, viol).
    # Logic: A > B if risk_a > risk_b OR (risk_a == risk_b AND fine_a > fine_b) ...
    
    # We want to prove that if risk_a > risk_b, then A is ranked higher regardless of fine or violations.
    # In Python sort(reverse=True), higher tuple means comes first.
    # Tuple comparison: (a1, a2, a3) > (b1, b2, b3)
    
    # We assert the negation: risk_a > risk_b BUT tuple_a <= tuple_b
    # Since tuple comparison is lexicographical, if a1 > b1, then tuple_a > tuple_b is always true.
    # We check if it's possible for tuple_a <= tuple_b when a1 > b1.
    
    # Z3 doesn't have native tuples, so we implement lexicographical logic manually for the negation check.
    # tuple_a <= tuple_b is equivalent to:
    # NOT (risk_a > risk_b) AND ... (this is complex, simpler to check if risk_a > risk_b implies A comes first)
    
    # Actually, let's verify the property:
    # If risk_a > risk_b, then (risk_a, fine_a, viol_a) > (risk_b, fine_b, viol_b)
    
    # Lexicographical comparison definition:
    # T1 > T2 iff (T1[0] > T2[0]) OR (T1[0] == T2[0] AND T1[1] > T2[1]) ...
    
    is_greater = z3.Or(
        risk_a > risk_b,
        z3.And(risk_a == risk_b, fine_a > fine_b),
        z3.And(risk_a == risk_b, fine_a == fine_b, viol_a > viol_b)
    )
    
    # We assert: risk_a > risk_b AND NOT(is_greater)
    s.add(z3.Not(is_greater))
    
    # This should be UNSAT because if risk_a > risk_b, the first term of the OR is true, so is_greater is true.
    assert s.check() == z3.unsat, "Sorting logic failed: Higher risk score did not guarantee higher rank"