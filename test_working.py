#!/usr/bin/env python3
import sys
sys.path.insert(0, 'src')

print("=" * 60)
print("RegWatch Working Test")
print("=" * 60)

# Test 1: Encryption Checker
print("\n1. Testing HIPAA Encryption Checker...")
try:
    from hipaa_encryption_checker import check_encryption
    result = check_encryption('test_codebases/st_marys_hospital/patient_api.py')
    print(f"✓ Encryption checker works!")
    print(f"  Result type: {type(result)}")
    print(f"  Violations found: {len(result) if isinstance(result, list) else 'dict/other'}")
    if isinstance(result, dict):
        print(f"  Keys: {list(result.keys())}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 2: Audit Logging Checker
print("\n2. Testing HIPAA Audit Logging Checker...")
try:
    from hipaa_audit_logging_checker import check_audit_logging
    result = check_audit_logging('test_codebases/st_marys_hospital/patient_api.py')
    print(f"✓ Audit checker works!")
    print(f"  Result type: {type(result)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 3: Access Control Checker
print("\n3. Testing HIPAA Access Control Checker...")
try:
    from hipaa_access_control_checker import check_access_control
    result = check_access_control('test_codebases/st_marys_hospital/patient_api.py')
    print(f"✓ Access control checker works!")
    print(f"  Result type: {type(result)}")
except Exception as e:
    print(f"✗ Error: {e}")

# Test 4: Change Tracker
print("\n4. Testing Change Tracker...")
try:
    from change_tracker import log_change
    print(f"✓ Change tracker has log_change function!")
except Exception as e:
    print(f"✗ Error: {e}")

print("\n" + "=" * 60)
print("Test Complete!")
print("=" * 60)
