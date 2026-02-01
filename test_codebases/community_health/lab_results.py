from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/api/lab-results/<patient_id>')
def get_lab_results(patient_id):
    # MEDIUM: Has basic structure
    # BAD: No authentication
    # BAD: No audit logging
    
    conn = sqlite3.connect('lab_results.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM results WHERE patient_id = {patient_id}")
    
    return jsonify(cursor.fetchall())

# Missing encryption
# Missing access controls
