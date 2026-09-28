from datetime import datetime, timedelta
from flask import Flask, jsonify
import requests

app = Flask(__name__)

# Fetch data
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5"
response = requests.get(url)
data = response.json()

# Clean data
cves = []

for item in data['vulnerabilities']:
    cve = item['cve']
    
    score = None

    # Try V3 score
    if 'cvssMetricV31' in item.get('metrics', {}):
        score = item['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    
    # Try V2 score if V3 not present
    elif 'cvssMetricV2' in item.get('metrics', {}):
        score = item['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']

    cves.append({
        "id": cve['id'],
        "published": cve['published'],
        "lastModified": cve['lastModified'],
        "score": score
    })

# API route
@app.route('/')
def home():
    return "Working"
@app.route('/cves', methods=['GET'])
def get_cves():
    return jsonify(cves)
@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    for cve in cves:
        if cve['id'] == cve_id:
            return cve
    return {"error": "CVE not found"}, 404
@app.route('/cves/year/<int:year>', methods=['GET'])
def get_cves_by_year(year):
    result = []
    
    for cve in cves:
        if str(year) in cve['id']:
            result.append(cve)
    
    return jsonify(result)
@app.route('/cves/last/<int:days>', methods=['GET'])
def get_last_n_days(days):
    result = []
    
    cutoff = datetime.now() - timedelta(days=days)

    for cve in cves:
        # convert string to datetime
        date = datetime.fromisoformat(cve['lastModified'].replace("Z",""))
        
        if date >= cutoff:
            result.append(cve)

    return jsonify(result)
@app.route('/cves/score/<min_score>', methods=['GET'])
def get_by_score(min_score):
    min_score = float(min_score)
    
    result = []
    
    for cve in cves:
        if cve['score'] is not None and cve['score'] >= min_score:
            result.append(cve)
    
    return jsonify(result)
# VERY IMPORTANT: must be LAST
if __name__ == '__main__':
    app.run(debug=True,port=5001)