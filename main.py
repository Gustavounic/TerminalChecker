import argparse
import configparser
import os
import requests

CONFIG_FILE = 'config.ini'

def load_api_key():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        return config.get('virustotal', 'api_key', fallback=None)
    else:
        return None

def check_virustotal(api_key, file_path=None, url_path=None):
    if file_path:
        return check_file(api_key, file_path)
    elif url_path:
        return check_url(api_key, url_path)
    else:
        print('You must provide a file path or URL for checking.')
        return None

def check_file(api_key, file_path):
    url_file_scan = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    try:
        with open(file_path, 'rb') as file:
            files = {'file': (file_path, file)}
            response = requests.post(url_file_scan, files=files, params=params)
            response.raise_for_status()
            result = response.json()
            resource = result.get('resource')
            if resource:
                return get_report(api_key, resource, type='file')
            else:
                print('Error: No resource returned.')
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to upload file: {e}")
    return None

def check_url(api_key, url_path):
    url_for_url_scan = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': url_path}
    try:
        response = requests.post(url_for_url_scan, data=params)
        response.raise_for_status()
        result = response.json()
        resource = result.get('resource')
        if resource:
            return get_report(api_key, resource, type='url')
        else:
            print('Error: No resource returned.')
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to submit URL: {e}")
    return None

def get_report(api_key, resource, type='file'):
    url_report = f'https://www.virustotal.com/vtapi/v2/{type}/report'
    params = {'apikey': api_key, 'resource': resource}
    try:
        response = requests.get(url_report, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: Unable to get report: {e}")
        return None

def display_result(result):
    positives = result.get('positives', 0)
    total = result.get('total', 0)
    if positives > 0:
        print(f'The resource is malicious! {positives}/{total} scanners detected it as malicious.')
    else:
        print('The resource is safe! No scanners detected it as malicious.')

def main():
    parser = argparse.ArgumentParser(description='Check file or URL on VirusTotal')
    parser.add_argument('-f', '--file_path', help='File path to be checked')
    parser.add_argument('-u', '--url_path', help='URL to be checked')
    args = parser.parse_args()

    api_key = load_api_key()

    if not api_key:
        parser.error("You need to define your API KEY in the configuration file!")

    if not args.file_path and not args.url_path:
        parser.error("At least one of the arguments --file_path or --url_path is required.")

    result = check_virustotal(api_key, args.file_path, args.url_path)

    if result:
        display_result(result)
    else:
        print('Could not check the resource.')

if __name__ == '__main__':
    main()
