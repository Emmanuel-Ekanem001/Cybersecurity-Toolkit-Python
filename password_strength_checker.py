
print("Password Checker!")
password = input("Enter the Password you want to check: ")
pass_length = len(password)
point = 0

# Length Checker
if pass_length <= 7:
    print("WEAK! Less than 8 characters: Very low security. Can be cracked in seconds using modern tools. Not safe for any meaningful account.")
elif pass_length >= 8 and pass_length <= 11:
    print("Moderate 8 to 11 characters: This password offers basic protection but is still at risk from advanced brute force attacks. Increasing the length will significantly improve its strength.")
    point += 25
elif pass_length >= 12 and pass_length <= 15:
    print("Strong 12 to 15 characters: This password is strong and meets common security standards. It provides good resistance against most brute force attacks. ")
    point += 40
elif pass_length >= 16:
    print("Very Strong 16 characters and above: This password is very strong. Its length provides high resistance to brute force attacks and is recommended for important or sensitive accounts.")
    point += 50

# Character Diversity Check
has_lowercase = False
has_uppercase = False
has_number = False
has_symbol = False

for char in password:
    if char.islower():
        has_lowercase = True
    elif char.isupper():
        has_uppercase = True
    elif char.isdigit():
        has_number = True
    else:
        has_symbol = True

if has_lowercase:
    print("Passwords includes lowercase!")
    point += 10
if has_uppercase:
    print("Passwords includes uppercase!")
    point += 10
if has_number:
    print("Passwords includes numbers!")
    point += 15
if has_symbol:
    print("Passwords includes special characters!")
    point += 15

# Word Pattern Check
common_words = [
    "password", "admin", "welcome", "login", "user", "root",
    "qwerty", "letmein", "iloveyou", "monkey", "dragon",
    "football", "baseball", "master", "hello", "freedom",
    "trustno1", "access", "secret"]
common_sequences = [
    "123", "1234", "12345", "123456", "0123",
    "abc", "abcd", "abcde",
    "qwerty", "asdf", "zxcv"]
common_repetitions = [
    "aaa", "bbb", "ccc",
    "111", "222", "333",
    "!!!", "@@@", "###"]

predictable_patterns = common_words + common_sequences + common_repetitions

has_predictable_patterns = False
for pattern in password:
    if pattern in predictable_patterns:
        has_predictable_patterns = True

if has_predictable_patterns:
    print("Password contains commonly used words and patterns!")
    point -= 50

# Final Scoring
if point <= 30:
    print("Password strength: WEAK. This password is easy to guess or crack and should not be used. Change it immediately.")
if point >= 31 and point <= 60:
    print("Password strength: MODERATE. This password offers basic protection but is vulnerable to advanced attacks. Consider improving it.")
if point >= 61 and point <= 80:
    print("Password strength: STRONG. This password meets modern security standards and is safe for most accounts.")
if point >= 81:
    print("Password strength: VERY STRONG. This password is highly secure and recommended for sensitive or important accounts.")
