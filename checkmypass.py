import requests
import hashlib
import sys
from requests.api import request


def request_api_data(query_data):
    url = 'https://api.pwnedpasswords.com/range/' + query_data
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leak_count(hashes, hash_to_check):
    # splits the api data into tuples of "tail" and "count"
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # generate a hash for the str using SHA1
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # only matching first 5 char of the hash for security
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    responce = request_api_data(first5_char)  # search api for match
    return get_password_leak_count(responce, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times. You should change your password.')
        else:
            print(f"{password} was not found. You are good to go.")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
