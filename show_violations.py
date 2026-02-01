#!/usr/bin/env python3
import sys
import json
sys.path.insert(0, 'src')

from hipaa_encryption_checker import check_encryption
from hipaa_audit_logging_checker import check_audit_logging
from hipaa_access_control_checker import check_access_control

print("=" * 70)
print("HIPAA Compliance Scan - St. Mary's Hospital")
print("=" * 70)

# Scan the bad hospital code
test_file = 'test_codebases/st_marys_hospital/patient_api.py'

print(f"\nScanning: {test_file}")
print("-" * 70)

# Encryption Check
print("\n🔐 ENCRYPTION CHECK:")
enc_result = check_encryption(test_file)
print(json.dumps(enc_result, indent=2))

# Audit Logging Check
print("\n📝 AUDIT LOGGING CHECK:")
audit_result = check_audit_logging(test_file)
print(json.dumps(audit_result, indent=2))

# Access Control Check
print("\n🔒 ACCESS CONTROL CHECK:")
access_result = check_access_control(test_file)
print(json.dumps(access_result, indent=2))

print("\n" + "=" * 70)
print("Scan Complete!")
print("=" * 70)
