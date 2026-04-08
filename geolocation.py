import os

import requests

BASE_URL = "https://api.ipgeolocation.io/ipgeo"


def get_ip_location(ip_address=None):
    api_key = os.getenv("IPGEOLOCATION_API_KEY")
    if not api_key:
        return None

    params = {
        "apiKey": api_key
    }

    if ip_address:
        params["ip"] = ip_address  # optional

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        return {
            "ip": data.get("ip"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "state": data.get("state_prov"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "isp": data.get("isp"),
            "organization": data.get("organization"),
        }

    except requests.exceptions.RequestException as e:
        print("Error:", e)
        return None


if __name__ == "__main__":
    # Option 1: Track your own IP
    location = get_ip_location()

    # Option 2: Track a specific IP
    # location = get_ip_location("8.8.8.8")

    if location:
        for key, value in location.items():
            print(f"{key}: {value}")
