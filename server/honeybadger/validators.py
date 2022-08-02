import re

# 1 upper, 1 lower, 1 special, 1 number, minimim 10 chars
PASSWORD_REGEX = r'(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*\(\)]).{10,}'
EMAIL_REGEX = r'[^@]+@[a-zA-Z\d-]+(?:\.[a-zA-Z\d-]+)+'

def is_valid_email(email):
    return bool(re.match(f'^{EMAIL_REGEX}$', email))

def is_valid_password(password):
    return bool(re.match(f'^{PASSWORD_REGEX}$', password))
