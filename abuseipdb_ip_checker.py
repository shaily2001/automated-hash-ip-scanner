import pandas as pd
import requests
import time
from openpyxl import Workbook
from openpyxl.worksheet.hyperlink import Hyperlink

# AbuseIPDB API details
API_KEY = '516a095d935275a0e24c4da12927f7d331ffcb5cdaf1151d7e36a12917588afefd4c859c727e569f'  # Replace with your actual API key
API_URL = 'https://api.abuseipdb.com/api/v2/check'

# Function to read IP addresses from the uploaded Excel file
def read_ip_excel(file_path):
    df = pd.read_excel(file_path)
    # Ensure the column containing IP addresses is named 'IP'
    if 'IP' not in df.columns:
        print("Error: The column with IP addresses is not found.")
        return None
    return df['IP']

# Function to defang an IP address (replace "." with "[.]")
def defang_ip(ip):
    return ip.replace('.', '[.]')

# Function to check the abuse information for each IP
def check_ip_abuse(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 365  # Reports from the last 365 days
    }

    # Send GET request to AbuseIPDB API
    response = requests.get(url, headers=headers, params=params)

    # Check if the request was successful
    if response.status_code == 200:
        data = response.json()

        # Extract the relevant information from the API response, handling potential missing keys
        abuse_confidence = data['data'].get('abuseConfidenceScore')
        total_reports = data['data'].get('totalReports')
        reference_link = f"https://www.abuseipdb.com/check/{ip}"

        # Return the data
        return abuse_confidence, total_reports, reference_link
    else:
        print(f"Error for IP {ip}: {response.status_code}")
        return None, None, None, None, None

# Function to process the IPs and create the output DataFrame
def process_ips(input_file):
    # Read the IPs from the input Excel file
    ip_list = read_ip_excel(input_file)

    if ip_list is None:
        return

    # List to store the results
    results = []

    # Iterate through each IP address and get the abuse details
    for ip in ip_list:
        abuse_confidence, total_reports, reference_link = check_ip_abuse(ip)

        # If data is returned, append to the results
        if abuse_confidence is not None:
            # Defang the IP address before saving it to the results
            defanged_ip = defang_ip(ip)

            results.append({
                'Ip Address': defanged_ip,  # Changed 'IP' to 'Ip Address'
                'Abuse Confidence Score': abuse_confidence,
                'Total Reports': total_reports,
                'Reference Link': reference_link
            })

    # Create a DataFrame from the results
    results_df = pd.DataFrame(results)

    # Save the results to a new Excel file using openpyxl for hyperlink formatting
    output_file = 'abuse_ip_reports_defanged.xlsx'

    # Create a workbook and a sheet using openpyxl
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        results_df.to_excel(writer, index=False, sheet_name='IP Abuse Report')

        # Access the workbook and the sheet
        workbook = writer.book
        sheet = workbook['IP Abuse Report']

        # Iterate through the 'Reference Link' column and add hyperlinks
        for row_num, reference_link in enumerate(results_df['Reference Link'], start=2):
            cell = sheet.cell(row=row_num, column=4)  # 'Reference Link' is the 6th column
            cell.hyperlink = reference_link
            cell.style = 'Hyperlink'  # Apply default hyperlink style (blue and underlined)

    print(f"Results have been saved to '{output_file}'.")

# Example of running the script
if __name__ == "__main__":
    # Specify the path to your uploaded Excel file
    input_file = '/content/Hdfcsales_scanning.xlsx'  # Replace with the path to your file

    # Process the IPs and generate the output
    process_ips(input_file)
