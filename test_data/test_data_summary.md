# RegWatch Test Data Summary

## Code Compliance Test Data

### St. Mary's Hospital (BAD - Score: 20/100)
**Files:** 3
**Expected Violations:** 25+
- ❌ No encryption libraries
- ❌ No authentication
- ❌ No audit logging
- ❌ SQL injection vulnerabilities
- ❌ Plain text passwords
- ❌ Debug mode in production
**Fine Exposure:** $3M - $10M

### Memorial Hospital (GOOD - Score: 95/100)
**Files:** 1
**Expected Violations:** 0-2 minor
- ✅ Encryption (AES-256-GCM)
- ✅ Authentication required
- ✅ Comprehensive audit logging
- ✅ Parameterized queries
- ✅ HTTPS only
**Fine Exposure:** <$50K

### Community Health (MEDIUM - Score: 65/100)
**Files:** 2
**Expected Violations:** 8-12
- ⚠️ Basic authentication (no MFA)
- ⚠️ Incomplete audit logging
- ⚠️ Outdated encryption (AES-256 vs AES-512)
- ❌ Some endpoints unprotected
**Fine Exposure:** $500K - $2M

## Data Compliance Test Data

### St. Mary's Patients (BAD - 100% Non-Compliant)
**Records:** 10
**Violations per record:** 4-6
- ❌ 10/10 SSNs unencrypted
- ❌ 7/10 missing consent signatures
- ❌ 10/10 missing withdrawal rights explanation
- ❌ 9/10 accessed without logging
- ❌ 3/10 missing consent dates

### Memorial Patients (GOOD - 100% Compliant)
**Records:** 10
**Violations per record:** 0
- ✅ 10/10 SSNs encrypted (AES-256-GCM)
- ✅ 10/10 have signed consent
- ✅ 10/10 withdrawal rights explained
- ✅ 10/10 access properly logged
- ✅ All fields complete

### Community Health Patients (MEDIUM - 30% Non-Compliant)
**Records:** 10
**Violations per record:** 1-3
- ⚠️ 3/10 SSNs unencrypted
- ⚠️ 2/10 missing consent signatures
- ⚠️ 4/10 missing withdrawal rights
- ⚠️ 3/10 not logged when accessed
- ⚠️ 2/10 missing consent dates

## Usage for Demo

1. **Worst Case Scenario:** St. Mary's code + data
2. **Best Practice:** Memorial code + data  
3. **Common Reality:** Community Health code + data

