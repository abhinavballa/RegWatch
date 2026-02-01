import pandas as pd
import pandera as pa
from pandera.typing import Series
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import os

# --- Configuration ---
RETENTION_YEARS = 7
CHUNK_SIZE = 10000
LARGE_FILE_THRESHOLD = 50000

class PatientRecordSchema(pa.SchemaModel):
    """
    Pandera SchemaModel defining the structure and basic validation rules for patient records.
    
    This schema enforces data types and basic structural integrity required for HIPAA compliance checks.
    More complex logic (cross-field validation, business rules) is handled in the validator functions.
    """
    patient_id: Series[str] = pa.Field(nullable=False, description="Unique identifier for the patient")
    
    # Consent Fields
    consent_signed: Series[bool] = pa.Field(nullable=True, coerce=True, description="Whether the patient has signed the consent form")
    consent_date: Series[pd.Timestamp] = pa.Field(nullable=True, coerce=True, description="Date when consent was signed")
    
    # PHI Encryption Fields
    encrypted_ssn: Series[str] = pa.Field(nullable=True, description="Encrypted Social Security Number")
    encrypted_medical_record: Series[str] = pa.Field(nullable=True, description="Encrypted Medical Record Data")
    
    # Access Log Fields
    last_access_date: Series[pd.Timestamp] = pa.Field(nullable=True, coerce=True, description="Timestamp of the last record access")
    last_access_user: Series[str] = pa.Field(nullable=True, description="User ID who last accessed the record")
    
    # Retention Fields
    created_date: Series[pd.Timestamp] = pa.Field(nullable=False, coerce=True, description="Date when the record was created")
    data_retention_expires: Optional[Series[pd.Timestamp]] = pa.Field(nullable=True, coerce=True, description="Explicit expiration date for data retention")

    class Config:
        coerce = True  # Automatically convert types where possible (e.g., string dates to datetime)
        strict = False # Allow extra columns in the input

def _validate_consent(row: pd.Series, violations: List[Dict[str, Any]], row_idx: int) -> None:
    """Checks if consent is signed and the date is valid."""
    if not row.get('consent_signed'):
        violations.append({
            "patient_id": row['patient_id'],
            "record_number": row_idx,
            "violation_type": "Missing Consent",
            "field_name": "consent_signed",
            "description": "Patient consent is not signed.",
            "severity": "High"
        })
    
    consent_date = row.get('consent_date')
    if pd.notna(consent_date):
        if consent_date > pd.Timestamp.now():
            violations.append({
                "patient_id": row['patient_id'],
                "record_number": row_idx,
                "violation_type": "Invalid Consent Date",
                "field_name": "consent_date",
                "description": "Consent date is in the future.",
                "severity": "High"
            })
    elif row.get('consent_signed'):
        # Signed but no date
        violations.append({
            "patient_id": row['patient_id'],
            "record_number": row_idx,
            "violation_type": "Missing Consent Date",
            "field_name": "consent_date",
            "description": "Consent is signed but date is missing.",
            "severity": "High"
        })

def _validate_encryption(row: pd.Series, violations: List[Dict[str, Any]], row_idx: int) -> None:
    """Checks if PHI fields are present and appear to be encrypted (length check)."""
    for field in ['encrypted_ssn', 'encrypted_medical_record']:
        val = row.get(field)
        # Basic heuristic: Encrypted strings (Base64/Hex) are usually long. 
        # Empty or very short strings suggest raw data or missing encryption.
        if pd.isna(val) or len(str(val)) < 10:
            violations.append({
                "patient_id": row['patient_id'],
                "record_number": row_idx,
                "violation_type": "Encryption Failure",
                "field_name": field,
                "description": f"Field {field} appears unencrypted or empty.",
                "severity": "Critical"
            })

def _validate_access_logs(row: pd.Series, violations: List[Dict[str, Any]], row_idx: int) -> None:
    """Checks if access logs are present. New records (<24h) are exempt."""
    created_date = row.get('created_date')
    is_new_record = False
    if pd.notna(created_date):
        if (pd.Timestamp.now() - created_date) < timedelta(hours=24):
            is_new_record = True

    if is_new_record:
        return

    if pd.isna(row.get('last_access_date')) or pd.isna(row.get('last_access_user')):
        violations.append({
            "patient_id": row['patient_id'],
            "record_number": row_idx,
            "violation_type": "Missing Access Logs",
            "field_name": "last_access_date/user",
            "description": "Access logs are missing for an established record.",
            "severity": "Medium"
        })

def _validate_retention(row: pd.Series, violations: List[Dict[str, Any]], row_idx: int) -> None:
    """Checks if data is within the retention period."""
    created_date = row.get('created_date')
    if pd.isna(created_date):
        # Schema validation usually catches this, but good to be safe
        violations.append({
            "patient_id": row['patient_id'],
            "record_number": row_idx,
            "violation_type": "Missing Creation Date",
            "field_name": "created_date",
            "description": "Creation date missing, cannot determine retention compliance.",
            "severity": "Medium"
        })
        return

    retention_limit = pd.Timestamp.now() - pd.DateOffset(years=RETENTION_YEARS)
    
    # If created_date is older than 7 years ago
    if created_date < retention_limit:
        violations.append({
            "patient_id": row['patient_id'],
            "record_number": row_idx,
            "violation_type": "Retention Policy Exceeded",
            "field_name": "created_date",
            "description": f"Record is older than {RETENTION_YEARS} years.",
            "severity": "Low"
        })

def validate_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Validates an in-memory Pandas DataFrame against HIPAA compliance rules.

    Args:
        df: The Pandas DataFrame containing patient records.

    Returns:
        A dictionary containing the validation report:
        {
            "total": int,
            "compliant": int,
            "non_compliant": int,
            "violations": List[Dict]
        }
    """
    report = {
        "total": 0,
        "compliant": 0,
        "non_compliant": 0,
        "violations": []
    }

    if df.empty:
        return report

    report["total"] = len(df)
    
    # 1. Schema Validation (Structural)
    try:
        # Lazy validation allows us to catch all schema errors rather than stopping at the first
        validated_df = PatientRecordSchema.validate(df, lazy=True)
    except pa.errors.SchemaErrors as err:
        # If schema validation fails, we extract the errors and map them to our report format
        # Note: Schema errors often mean we can't trust the data for logic checks, 
        # but we will try to proceed with the original DF for logic checks where possible.
        validated_df = df # Fallback to original for logic checks
        
        for failure in err.failure_cases.itertuples():
            # failure_cases dataframe has columns: schema_context, column, check, check_number, failure_case, index
            row_idx = failure.index
            patient_id = "Unknown"
            if row_idx in df.index and 'patient_id' in df.columns:
                patient_id = df.at[row_idx, 'patient_id']

            report["violations"].append({
                "patient_id": patient_id,
                "record_number": int(row_idx) if pd.notna(row_idx) else -1,
                "violation_type": "Schema Violation",
                "field_name": str(failure.column),
                "description": f"Schema check failed: {failure.check}",
                "severity": "Critical"
            })

    # 2. Logic Validation (Business Rules)
    # We iterate through rows. For very large DFs, vectorization is preferred, 
    # but row iteration allows for granular, complex multi-field error reporting required here.
    
    # To track which rows have violations to calculate 'compliant' count correctly
    violation_indices = set()
    
    # Add schema violation indices first
    for v in report["violations"]:
        if v["record_number"] != -1:
            violation_indices.add(v["record_number"])

    for idx, row in validated_df.iterrows():
        current_violations = []
        
        # Skip logic checks if critical columns are missing (handled by Schema validation)
        if 'patient_id' not in row:
            continue

        _validate_consent(row, current_violations, idx)
        _validate_encryption(row, current_violations, idx)
        _validate_access_logs(row, current_violations, idx)
        _validate_retention(row, current_violations, idx)

        if current_violations:
            violation_indices.add(idx)
            report["violations"].extend(current_violations)

    report["non_compliant"] = len(violation_indices)
    report["compliant"] = report["total"] - report["non_compliant"]

    return report

def validate_records(csv_path: str) -> Dict[str, Any]:
    """
    Reads a CSV file and validates patient records. Supports chunking for large files.

    Args:
        csv_path: Path to the CSV file.

    Returns:
        A dictionary containing the aggregated validation report.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    # Determine if we need chunking
    file_size_rows = 0
    try:
        # Quick check for line count (approximate row count)
        with open(csv_path, 'r', encoding='utf-8') as f:
            for i, _ in enumerate(f):
                if i > LARGE_FILE_THRESHOLD:
                    file_size_rows = i
                    break
            file_size_rows = i
    except Exception:
        # If we can't read it easily, assume it might be large or just let pandas handle it
        pass

    use_chunking = file_size_rows >= LARGE_FILE_THRESHOLD

    aggregated_report = {
        "total": 0,
        "compliant": 0,
        "non_compliant": 0,
        "violations": []
    }

    if use_chunking:
        chunk_iterator = pd.read_csv(csv_path, chunksize=CHUNK_SIZE)
        
        # We need to maintain a continuous index across chunks for reporting
        global_index_offset = 0
        
        for chunk in chunk_iterator:
            # Reset index of chunk to match global file position
            chunk.index += global_index_offset
            
            chunk_report = validate_dataframe(chunk)
            
            aggregated_report["total"] += chunk_report["total"]
            aggregated_report["compliant"] += chunk_report["compliant"]
            aggregated_report["non_compliant"] += chunk_report["non_compliant"]
            aggregated_report["violations"].extend(chunk_report["violations"])
            
            global_index_offset += len(chunk)
            
    else:
        df = pd.read_csv(csv_path)
        aggregated_report = validate_dataframe(df)

    return aggregated_report