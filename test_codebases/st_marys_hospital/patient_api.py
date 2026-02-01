import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/patient/<patient_id>')
def get_patient(patient_id):
    # VIOLATION: No authentication
    # VIOLATION: Unencrypted database
    # VIOLATION: SQL injection
    # VIOLATION: No audit logging
    
    conn = sqlite3.connect('patients.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM patients WHERE id = {patient_id}")
    patient = cursor.fetchone()
    
    return {
        'ssn': patient[2],  # Sending SSN unencrypted!
        'diagnosis': patient[3]
    }
