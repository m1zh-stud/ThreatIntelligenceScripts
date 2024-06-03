import whois
import requests
import datetime
import json
import os

def get_or_set_env_variable(var_name):
    var_value = os.getenv(var_name)
    if var_value is None:
        var_value = input(f"Please enter the value for {var_name}: ")
        os.environ[var_name] = var_value
    return var_value

def get_whois_data(ip):
    try:
        w = whois.whois(ip)
        return f"domain_name: {w.domain_name}\nCountry code:{w.country}\nCity:{w.city}\naddress:{w.address}"
    except Exception as e:
        return str(e)

def check_virustotal(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "x-apikey": os.getenv('VirusTotalAPI')  # API_KEY
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            reputation = data['data']['attributes']['reputation']
            last_analysis_stats = data['data']['attributes']['last_analysis_stats']
            last_analysis_date = datetime.datetime.utcfromtimestamp(data['data']['attributes']['last_analysis_date']).strftime('%d/%m/%Y')
            return f"Репутация: {reputation} \nlast_analysis_stats: {last_analysis_stats}\nlast_analysis_date: {last_analysis_date}"
        else:
            return f"Error: {response.status_code}"
    except Exception as e:
        return str(e)
def AlienVaultOTX(ip):
    api_key = os.getenv('AlienVaultAPI')
    url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/url_list'
    url2 = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware'

    headers = {'X-OTX-API-KEY': api_key,}
    try:
        response = requests.get(url, headers=headers)
        response2 = requests.get(url2, headers=headers)
        if response.status_code == 200 and response2.status_code == 200:
            data = response.json()
            reputation = data.get('pulse_info', {}).get('count', 0)
            data2 = response2.json()
            hashes_data = data2.get('data', [])
            hashes = [item['hash'] for item in hashes_data]
            names = [item['detections']['avg'] for item in hashes_data]
            return f"Репутация: {reputation}\nХэши: {hashes[:3]}\nНазвания вредоносов: {names[:3]}"

        else:
            return f"Error: {response.status_code}, {response2.status_code}"
    except Exception as e:
        print("Error occurred:", e)
        return None, None

def main():
    ip = input("Введите IP-адрес: ")
    #path = input("Введите путь до файла с API ключами: ")
    #with open(path, 'r') as f:
        #data_keys = json.load(f)
    #get_or_set_env_variable('VirusTotalAPI')
    #get_or_set_env_variable('AlienVaultAPI')
    get_or_set_env_variable('PATH')
    print("\nWHOIS данные:")
    print(get_whois_data(ip))
    print("\nVirusTotal результаты:")
    print(check_virustotal(ip))
    print("\nAlienVault OTX результаты:")
    print(AlienVaultOTX(ip))


if __name__ == "__main__":
    main()