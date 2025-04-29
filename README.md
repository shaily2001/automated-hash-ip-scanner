# Hash & IP Risk Assessment Automation

Python-based script for bulk threat intelligence lookups using **VirusTotal** and **AbuseIPDB** APIs. This tool streamlines the analysis of **malware file hashes** and **suspicious IP addresses**, providing fast and accurate risk insights.

---

## Features

- **VirusTotal API Integration**  
  Analyze up to 250+ file hashes to check for malicious detections.

- **AbuseIPDB API Integration**  
  Evaluate over 1000+ IP addresses for abuse confidence, total reports, and threat indicators.

- **Fully Automated**  
  Eliminates manual analysis, reducing effort by 75% and improving response time.

- **Excel Input & Output Support**  
  Read hashes and IPs from `.xlsx` files and export results with hyperlinks to VirusTotal and AbuseIPDB reports.

---

## Technologies Used

- Python 3.x  
- `pandas`, `openpyxl`, `requests`  
- VirusTotal API v3  
- AbuseIPDB API v2  

---

## Usage

1. **Install dependencies:**

   ```bash
   pip install pandas openpyxl requests
Configure API Keys:

Replace the placeholders in both scripts with your VirusTotal and AbuseIPDB API keys.

Run the scripts:

python hash_checker.py
python ip_checker.py

Check Output:

Output Excel files will contain scan results with hyperlinks to detailed reports.

## Example Output

| Hash / IP Address | Score             | Reports | Reference         |
|-------------------|------------------|---------|-------------------|
| d5d59693f6ee671a4cfa170b43e8079d7c7a22f50ad87ff3d6e50069a242757a        | Malicious (26/70) | -       | [VirusTotal Link](https://www.virustotal.com/gui/file/d5d59693f6ee671a4cfa170b43e8079d7c7a22f50ad87ff3d6e50069a242757a) |
| 160.191.51.211      | 100             | 493     | [AbuseIPDB Link](https://www.abuseipdb.com/check/160.191.51.211) |


