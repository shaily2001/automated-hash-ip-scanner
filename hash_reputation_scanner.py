import requests
import pandas as pd
import openpyxl
import time
import re

# Replace with your VirusTotal API key
api_key = '0c463dd26caec3db02a10ce0e266ebd1d3922962ae30f98df9959a35b4cc133b'

def check_hash_reputation(hash_value):
    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {
        'x-apikey': api_key,
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise error for bad responses

        data = response.json()
        if 'data' in data:
            attributes = data['data']['attributes']
            last_analysis_stats = attributes['last_analysis_stats']
            malicious = last_analysis_stats['malicious']

              # construct the link to the virustotal page
            link = f"https://www.virustotal.com/gui/file/{hash_value}"

            return {
                'Hash': hash_value,
                'Malicious': f"Number of security vendors that flagged the hash as malicious: {malicious}",
                'Link': link
            }
        else:
            return {
                'Hash': hash_value,
                'Malicious': 0,
            }

    except requests.exceptions.HTTPError as e:
        print(f"Error: {e}")
        return {
            'Hash': hash_value,
            'Malicious': f"No match Found!",
        }
    # Wait for a specified amount of time
    time.sleep(1)  # Wait for 1 second, adjust as needed

def check_hashes_in_excel(input_file, output_file):
    # Load input Excel file
    df = pd.read_excel(input_file, engine='openpyxl')

    # Initialize a list to store results
    results = []

    # Check reputation for each hash value
    for index, row in df.iterrows():
        hash_value = row['Hash']
        result = check_hash_reputation(hash_value)
        results.append(result)

    # Create a DataFrame from results
    results_df = pd.DataFrame(results)

    # Save results to output Excel file
    results_df.to_excel(output_file, index=False, engine='openpyxl')
    print(f"Results saved to '{output_file}'.")

def check_hashes_in_excel(input_file, output_file):
    # Load input Excel file, explicitly specifying the column containing hashes
    df = pd.read_excel(input_file, engine='openpyxl')

    # Check if 'Hash' column exists, if not, try to guess the correct column
    if 'Hash' not in df.columns:
        # Assuming the first column contains the hashes if 'Hash' is not found
        hash_column = df.columns[0]
        print(f"Warning: 'Hash' column not found. Using '{hash_column}' as the hash column.")
    else:
        hash_column = 'Hash'

    # Initialize a list to store results
    results = []
    refer_link=[]

    # Check reputation for each hash value
    for index, row in df.iterrows():
        hash_value = row[hash_column]  # Use the identified hash column
        result = check_hash_reputation(hash_value)
        results.append(result)

    # Create a DataFrame from results
    results_df = pd.DataFrame(results)

    # Save results to output Excel file
    results_df.to_excel(output_file, index=False, engine='openpyxl')
    print(f"Results saved to '{output_file}'.")

    # Example usage
if __name__ == "__main__":
    input_file = '/content/Hdfcsales_scanning.xlsx'  # Replace with your input Excel file path
    output_file = '/content/result.xlsx'  # Replace with desired output Excel file path
    check_hashes_in_excel(input_file, output_file)
