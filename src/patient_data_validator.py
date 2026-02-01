"""
patient_data_validator.py

This module implements validation logic for patient records within the RegWatch compliance
monitoring system. It ensures adherence to HIPAA data handling requirements regarding
consent, PHI encryption, access logging, and data retention.

The module leverages Pandas for data manipulation and Pandera for schema-based validation.
It supports processing of large datasets via chunking to maintain memory efficiency.

HIPAA Compliance Checks:
1.  **Consent**: Verifies that `consent_signed` is True and `consent_date` is valid.
2.  **Encryption**: Checks that PHI fields (`encrypted_ssn`, `encrypted_medical_record`)
    contain data that appears encrypted (non-empty, minimum length).
3.  **Access Logs**: Ensures `last_access_date` and `last_access_user` are recorded to
    maintain an audit trail.
4.  **Retention**: Verifies records are within the 7-year retention period mandated by HIPAA.
"""

import pandas as pd
import pandera as pa
from pandera.typing import Series
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
import logging

# Handle different pandera versions
try:
    from pandera import SchemaModel
except (ImportError, AttributeError):
    # For pandera >= 0.17, SchemaModel is in a different location
    try:
        from pandera.api.pandas.model import SchemaModel
    except (ImportError, AttributeError):
        # Create a simple fallback
        SchemaModel = type('SchemaModel', (), {})

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
RETENTION_YEARS = 7
CHUNK_SIZE = 10000
MIN_ENCRYPTED_LENGTH = 10  # Heuristic: encrypted strings are usually long

class PatientRecordSchema(SchemaModel):
    """
    Pandera SchemaModel defining the expected structure and basic validation rules
    for patient records.
    """
    patient_id: Series[str] = pa.Field(nullable=False, description="Unique identifier for the patient")
    
    # Consent fields
    consent_signed: Series[bool] = pa.Field(nullable=False, description="Whether the patient has signed the consent form")
    consent_date: Series[pd.Timestamp] = pa.Field(nullable=True, description="Date when consent was signed")

    # PHI fields (Must be encrypted)
    encrypted_ssn: Series[str] = pa.Field(nullable=True, description="Encrypted Social Security Number")
    encrypted_medical_record: Series[str] = pa.Field(nullable=True, description="Encrypted Medical Record Data")

    # Access Logs
    last_access_date: Series[pd.Timestamp] = pa.Field(nullable=True, description="Timestamp of the last record access")
    last_access_user: Series[str] = pa.Field(nullable=True, description="User ID who last accessed the record")

    # Metadata
    created_date: Series[pd.Timestamp] = pa.Field(nullable=False, description="Date the record was created")

    class Config:
        coerce = True  # Attempt to convert types (e.g., string dates to datetime)
        strict = False # Allow extra columns, but validate the ones defined

def _check_retention_compliance(created_date: pd.Timestamp) -> bool:
    """
    Check if the record is within the 7-year HIPAA retention period.
    """
    if pd.isna(created_date):
        return False
    cutoff_date = datetime.now() - timedelta(days=365 * RETENTION_YEARS)
    return created_date >= cutoff_date

def _is_encrypted_heuristic(value: Any) -> bool:
    """
    Heuristic check for encryption: non-empty string with sufficient length.
    Real encryption validation would require key attempts or format checks.
    """
    if pd.isna(value) or not isinstance(value, str):
        return False
    return len(value) > MIN_ENCRYPTED_LENGTH

def validate_dataframe(df: pd.DataFrame, start_row_index: int = 0) -> Dict[str, Any]:
    """
    Validates an in-memory Pandas DataFrame against HIPAA compliance rules.

    Args:
        df: The Pandas DataFrame to validate.
        start_row_index: The starting index for row numbering (useful for chunked processing).

    Returns:
        A dictionary containing the validation report with keys:
        - total: Total records processed
        - compliant: Count of compliant records
        - non_compliant: Count of non-compliant records
        - violations: List of violation details
    """
    violations = []
    
    # 1. Schema Validation (Structural Integrity)
    # We use lazy=True to capture all schema errors rather than stopping at the first one.
    try:
        PatientRecordSchema.validate(df, lazy=True)
    except pa.errors.SchemaErrors as err:
        for failure in err.failure_cases.itertuples():
            # failure_cases dataframe columns: index, failure_case, schema_context, column, check, check_number
            row_idx = failure.index + start_row_index if isinstance(failure.index, int) else "N/A"
            
            violations.append({
                "patient_id": df.iloc[failure.index]['patient_id'] if 'patient_id' in df.columns and isinstance(failure.index, int) and failure.index < len(df) else "Unknown",
                "record_number": row_idx,
                "violation_type": "Schema Violation",
                "field_name": failure.column,
                "description": f"Schema check failed: {failure.check}",
                "severity": "Critical"
            })

    # 2. Business Logic Validation (Row-wise checks)
    compliant_count = 0
    
    for idx, row in df.iterrows():
        record_violations = []
        row_num = idx + start_row_index
        pid = row.get('patient_id', 'Unknown')

        # --- Consent Check ---
        if not row.get('consent_signed', False):
            record_violations.append({
                "patient_id": pid, "record_number": row_num,
                "violation_type": "Consent Missing",
                "field_name": "consent_signed",
                "description": "Patient has not signed consent form.",
                "severity": "High"
            })
        
        consent_date = row.get('consent_date')
        if pd.notna(consent_date) and consent_date > datetime.now():
             record_violations.append({
                "patient_id": pid, "record_number": row_num,
                "violation_type": "Invalid Consent Date",
                "field_name": "consent_date",
                "description": "Consent date is in the future.",
                "severity": "High"
            })

        # --- Encryption Check ---
        if not _is_encrypted_heuristic(row.get('encrypted_ssn')):
            record_violations.append({
                "patient_id": pid, "record_number": row_num,
                "violation_type": "Unencrypted PHI",
                "field_name": "encrypted_ssn",
                "description": "SSN field appears unencrypted or empty.",
                "severity": "Critical"
            })
        
        if not _is_encrypted_heuristic(row.get('encrypted_medical_record')):
            record_violations.append({
                "patient_id": pid, "record_number": row_num,
                "violation_type": "Unencrypted PHI",
                "field_name": "encrypted_medical_record",
                "description": "Medical record field appears unencrypted or empty.",
                "severity": "Critical"
            })

        # --- Access Log Check ---
        created_date = row.get('created_date')
        is_new_record = False
        if pd.notna(created_date):
            if (datetime.now() - created_date).total_seconds() < 86400:
                is_new_record = True

        if not is_new_record:
            if pd.isna(row.get('last_access_date')):
                record_violations.append({
                    "patient_id": pid, "record_number": row_num,
                    "violation_type": "Missing Audit Log",
                    "field_name": "last_access_date",
                    "description": "Missing last access timestamp for established record.",
                    "severity": "Medium"
                })
            if pd.isna(row.get('last_access_user')):
                record_violations.append({
                    "patient_id": pid, "record_number": row_num,
                    "violation_type": "Missing Audit Log",
                    "field_name": "last_access_user",
                    "description": "Missing user ID for last access.",
                    "severity": "Medium"
                })

        # --- Data Retention Check ---
        if pd.notna(created_date):
            if not _check_retention_compliance(created_date):
                record_violations.append({
                    "patient_id": pid, "record_number": row_num,
                    "violation_type": "Retention Policy",
                    "field_name": "created_date",
                    "description": f"Record exceeds {RETENTION_YEARS} year retention period.",
                    "severity": "Low"
                })

        if not record_violations:
            compliant_count += 1
        else:
            violations.extend(record_violations)

    return {
        "total": len(df),
        "compliant": compliant_count,
        "non_compliant": len(df) - compliant_count,
        "violations": violations
    }

def validate_records(csv_path: str) -> Dict[str, Any]:
    """
    Validates patient records from a CSV file. Supports chunked processing for large files.

    Args:
        csv_path: Path to the CSV file.

    Returns:
        A dictionary containing the aggregated validation report.
    """
    report = {
        "total": 0,
        "compliant": 0,
        "non_compliant": 0,
        "violations": []
    }

    try:
        with pd.read_csv(csv_path, chunksize=CHUNK_SIZE, parse_dates=['consent_date', 'last_access_date', 'created_date']) as reader:
            for i, chunk in enumerate(reader):
                logger.info(f"Processing chunk {i+1}...")
                start_row = (i * CHUNK_SIZE) + 1
                chunk_result = validate_dataframe(chunk, start_row_index=start_row)
                report["total"] += chunk_result["total"]
                report["compliant"] += chunk_result["compliant"]
                report["non_compliant"] += chunk_result["non_compliant"]
                report["violations"].extend(chunk_result["violations"])

    except FileNotFoundError:
        logger.error(f"File not found: {csv_path}")
        return {"error": "File not found", "violations": []}
    except pd.errors.EmptyDataError:
        logger.error("CSV file is empty")
        return {"error": "Empty CSV file", "violations": []}
    except Exception as e:
        logger.error(f"An error occurred during processing: {str(e)}")
        return {"error": str(e), "violations": []}

    return report