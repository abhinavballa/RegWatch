#!/usr/bin/env python3
import sys
import os

# Add src to path
sys.path.insert(0, 'src')
os.chdir(os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("RegWatch Integration Test")
print("=" * 60)

# Test imports
print("\n1. Testing module imports...")

modules_to_test = [
    ('hipaa_encryption_checker', 'analyze'),
    ('hipaa_audit_logging_checker', 'analyze'),
    ('hipaa_access_control_checker', 'analyze'),
    ('patient_data_validator', 'validate_records'),
    ('change_tracker', 'ChangeTracker'),
    ('voice_service', 'VoiceService'),
]

imported = {}
for module_name, func_name in modules_to_test:
    try:
        module = __import__(module_name)
        if hasattr(module, func_name):
            imported[module_name] = getattr(module, func_name)
            print(f"  ✓ {module_name}.{func_name}")
        else:
            print(f"  ⚠ {module_name} imported but missing {func_name}")
            imported[module_name] = None
    except ImportError as e:
        print(f"  ✗ {module_name}: {e}")
        imported[module_name] = None
    except Exception as e:
        print(f"  ✗ {module_name}: {e}")
        imported[module_name] = None

# Test checkers
print("\n2. Testing HIPAA checkers on sample code...")

if imported.get('hipaa_encryption_checker'):
    try:
        analyze = imported['hipaa_encryption_checker']
        result = analyze('test_codebases/st_marys_hospital/')
        print(f"  ✓ Encryption checker ran: {type(result)}")
        if isinstance(result, (list, dict)):
            print(f"    Found violations: {len(result) if isinstance(result, list) else 'dict returned'}")
    except Exception as e:
        print(f"  ✗ Encryption checker error: {e}")

if imported.get('hipaa_audit_logging_checker'):
    try:
        analyze = imported['hipaa_audit_logging_checker']
        result = analyze('test_codebases/st_marys_hospital/')
        print(f"  ✓ Audit logging checker ran: {type(result)}")
    except Exception as e:
        print(f"  ✗ Audit logging checker error: {e}")

if imported.get('hipaa_access_control_checker'):
    try:
        analyze = imported['hipaa_access_control_checker']
        result = analyze('test_codebases/st_marys_hospital/')
        print(f"  ✓ Access control checker ran: {type(result)}")
    except Exception as e:
        print(f"  ✗ Access control checker error: {e}")

# Test patient data validator
print("\n3. Testing patient data validator...")

if imported.get('patient_data_validator'):
    try:
        validate = imported['patient_data_validator']
        result = validate('test_data/sample_patients.csv')
        print(f"  ✓ Patient validator ran: {type(result)}")
    except Exception as e:
        print(f"  ✗ Patient validator error: {e}")

print("\n" + "=" * 60)
print("Integration test complete!")
print("=" * 60)
