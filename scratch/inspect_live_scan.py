import requests

base_url = "http://localhost:8000"

print("Checking available scans in backend server...")
try:
    r = requests.get(f"{base_url}/api/v1/scans")
    print(f"Status Code: {r.status_code}")
    print("Scans Response:", r.json())
except Exception as exc:
    print("Error:", exc)
