import requests
import hashlib
import sys
from requests.api import request
import smtplib
from email.message import EmailMessage
from string import Template
from pathlib import Path

email = EmailMessage()
email['from'] = 'Tony Sun'
email['to'] = 'sunwuyue@live.com'
email['subject'] = 'Monthly Passcheck'
# Use the task scheduler in Windows to automate running this script monthly!!


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
    s = ''
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times. You should change your password.')
            s += f'{password} was found {count} times. You should change your password.\n'
        else:
            print(f"{password} was not found. You are good to go.")
            s += f"{password} was not found. You are good to go.\n"
    email.set_content(s, 'html')
    with smtplib.SMTP(host='smtp.gmail.com', port=587) as smtp:
        smtp.ehlo()
        smtp.starttls()
        smtp.login('tedxnguyenx@gmail.com', 'Aa020829')
        smtp.send_message(email)


if __name__ == "__main__":
    main(sys.argv[1:])
