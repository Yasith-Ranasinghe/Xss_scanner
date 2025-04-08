import sqlite3
import csv
import json
import os
from datetime import datetime
import html

class ReportGenerator:
    def __init__(self, db_name="scan_reports.db"):
        self.db_name = db_name
        self._initialize_db()

    def _initialize_db(self):
        """Initialize the SQLite database with the required tables."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    result TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def save_report(self, url, scan_type, result):
        """Save a scan report to the database."""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_reports (url, scan_type, result)
                VALUES (?, ?, ?)
            """, (url, scan_type, json.dumps(result)))
            conn.commit()

    def get_latest_reports(self, limit=10, scan_type=None):
        """Get the latest scan reports, optionally filtered by scan_type."""
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            if scan_type:
                cursor.execute("""
                    SELECT * FROM scan_reports 
                    WHERE scan_type = ? 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (scan_type, limit))
            else:
                cursor.execute("""
                    SELECT * FROM scan_reports 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                """, (limit,))
            
            rows = cursor.fetchall()
        
        # Convert rows to dictionaries
        reports = []
        for row in rows:
            report = dict(row)
            report['result'] = json.loads(report['result'])
            reports.append(report)
            
        return reports

    def generate_csv_report(self, output_file="report.csv", scan_type=None):
        """Generate a CSV report from the database, optionally filtered by scan_type."""
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            if scan_type:
                cursor.execute("SELECT * FROM scan_reports WHERE scan_type = ?", (scan_type,))
            else:
                cursor.execute("SELECT * FROM scan_reports")
                
            rows = cursor.fetchall()

        with open(output_file, mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "URL", "Scan Type", "Result", "Timestamp"])
            
            for row in rows:
                # Format the result JSON for better readability in CSV
                result_dict = json.loads(row[3])
                formatted_result = json.dumps(result_dict, indent=2)
                writer.writerow([row[0], row[1], row[2], formatted_result, row[4]])
                
        return output_file

    def generate_json_report(self, output_file="report.json", scan_type=None, pretty=True):
        """Generate a JSON report from the database, optionally filtered by scan_type."""
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            if scan_type:
                cursor.execute("SELECT * FROM scan_reports WHERE scan_type = ?", (scan_type,))
            else:
                cursor.execute("SELECT * FROM scan_reports")
                
            rows = cursor.fetchall()

        report = [
            {
                "id": row[0],
                "url": row[1],
                "scan_type": row[2],
                "result": json.loads(row[3]),
                "timestamp": row[4]
            }
            for row in rows
        ]

        with open(output_file, "w") as file:
            if pretty:
                json.dump(report, file, indent=4)
            else:
                json.dump(report, file)
                
        return output_file

    def generate_html_report(self, output_file="report.html", scan_type=None):
        """Generate an HTML report from the database, optionally filtered by scan_type."""
        # Ensure the output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        
        # Get the reports
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            if scan_type:
                cursor.execute("SELECT * FROM scan_reports WHERE scan_type = ?", (scan_type,))
            else:
                cursor.execute("SELECT * FROM scan_reports")
                
            rows = cursor.fetchall()

        # Start creating the HTML content
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .report {{ background-color: #f9f9f9; padding: 15px; margin: 10px 0; border-radius: 5px; border: 1px solid #ddd; }}
        .report h3 {{ margin-top: 0; }}
        .xss {{ background-color: #ffe6e6; }}
        .phishing {{ background-color: #e6f7ff; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
        .timestamp {{ color: #777; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
"""

        # Add filter links if no specific scan type was selected
        if not scan_type:
            html_content += """
    <div>
        <p>Filter by scan type:</p>
        <ul>
            <li><a href="xss_report.html">XSS Scan Reports</a></li>
            <li><a href="phishing_report.html">Phishing Scan Reports</a></li>
        </ul>
    </div>
"""
        
        # Add report type title
        if scan_type == "xss":
            html_content += "<h2>XSS Vulnerability Scan Reports</h2>"
        elif scan_type == "phishing":
            html_content += "<h2>Phishing Analysis Reports</h2>"
        else:
            html_content += "<h2>All Security Scan Reports</h2>"
            
        # Process each report
        for row in rows:
            report_id = row[0]
            url = row[1]
            report_type = row[2]
            result = json.loads(row[3])
            timestamp = row[4]
            
            # Start report div with appropriate class
            html_content += f"""
    <div class="report {report_type}">
        <h3>Report #{report_id}: {url}</h3>
        <p class="timestamp">Scan performed on: {timestamp}</p>
        <p><strong>Scan Type:</strong> {report_type.upper()}</p>
"""
            
            # Format the report content based on type
            if report_type == "xss":
                if "type" in result:
                    html_content += f"<p><strong>Vulnerability Type:</strong> {result.get('type', 'Standard')}</p>"
                    
                    if result.get('type') == 'DOM-based' and 'details' in result:
                        html_content += f"<p><strong>Sink:</strong> {result['details'].get('sink', 'N/A')}</p>"
                        html_content += f"<p><strong>Code Snippet:</strong></p>"
                        html_content += f"<pre>{html.escape(result['details'].get('code', 'N/A'))}</pre>"
                    else:
                        html_content += f"<p><strong>Vector:</strong> {result.get('vector', 'Form')}</p>"
                        html_content += f"<p><strong>Payload:</strong> <code>{html.escape(result.get('payload', 'N/A'))}</code></p>"
                else:
                    # Just dump the JSON for any other structure
                    html_content += f"<pre>{html.escape(json.dumps(result, indent=2))}</pre>"
                    
            elif report_type == "phishing":
                if isinstance(result, dict) and "is_phishing" in result:
                    # URL information
                    html_content += "<h4>URL Analysis</h4>"
                    html_content += f"<p><strong>Domain:</strong> {result.get('domain', 'N/A')}</p>"
                    html_content += f"<p><strong>Subdomain:</strong> {result.get('subdomain', 'N/A') or 'None'}</p>"
                    html_content += f"<p><strong>TLD:</strong> {result.get('tld', 'N/A')}</p>"
                    
                    # Security indicators
                    html_content += "<h4>Security Indicators</h4>"
                    is_https = result.get("is_https", False)
                    https_text = "Yes" if is_https else "No"
                    https_color = "green" if is_https else "red"
                    html_content += f"<p><strong>HTTPS:</strong> <span style='color: {https_color};'>{https_text}</span></p>"
                    
                    is_suspicious_tld = result.get("is_suspicious_tld", False)
                    tld_text = "Yes" if is_suspicious_tld else "No"
                    tld_color = "red" if is_suspicious_tld else "green"
                    html_content += f"<p><strong>Suspicious TLD:</strong> <span style='color: {tld_color};'>{tld_text}</span></p>"
                    
                    # Phishing verdict
                    is_phishing = result.get("is_phishing", False)
                    verdict_text = "Likely Phishing" if is_phishing else "Probably Safe"
                    verdict_color = "red" if is_phishing else "green"
                    html_content += f"<h4>Verdict: <span style='color: {verdict_color};'>{verdict_text}</span></h4>"
                    
                    # Add phishing score if available
                    if "phishing_score" in result:
                        score = result["phishing_score"]
                        html_content += f"<p><strong>Phishing Score:</strong> {score:.2f}</p>"
                else:
                    # Just dump the JSON for any other structure
                    html_content += f"<pre>{html.escape(json.dumps(result, indent=2))}</pre>"
            else:
                # Just dump the JSON for any other type
                html_content += f"<pre>{html.escape(json.dumps(result, indent=2))}</pre>"
                
            # Close the report div
            html_content += "</div>"
            
        # Close the HTML document
        html_content += """
</body>
</html>
"""

        # Write the HTML to file
        with open(output_file, "w") as file:
            file.write(html_content)
            
        return output_file

    def delete_report(self, report_id):
        """Delete a report from the database by ID."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_reports WHERE id = ?", (report_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception:
            return False
            
    def purge_reports(self, days=30):
        """Purge reports older than the specified number of days."""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM scan_reports WHERE datetime(timestamp) < datetime('now', ?)", 
                    (f"-{days} days",)
                )
                conn.commit()
                return cursor.rowcount
        except Exception:
            return 0