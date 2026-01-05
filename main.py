while True:
    print("\n=== Cybersecurity Toolkit ===")
    print("1. URL Scanner")
    print("2. Password Strength Checker")
    print("3. Exit")

    try:
        option = int(input("Select an option: "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        continue

    # TOOL 1: URL Scanner
    if option == 1:
        print("\n[ URL Scanner Selected ]\n")
        # Input the URL
        url = input("Enter the URL: ")
        print("Url:", url)

        # Cleaning the URL

        def cleaning_url(clean_url):
            clean_url = clean_url.replace(" ", "")
            clean_url = clean_url.lower()
            if "http://" not in clean_url and "https://" not in clean_url:
                clean_url = "http://" + clean_url
            return clean_url

        risk_counter = 0

        # Connecting clean function with User Input
        cleaned_url = cleaning_url(url)

        # Url Length Checker
        cleaned_url_length = len(cleaned_url)
        if cleaned_url_length > 150:
            print("This URL is unusually long. Long URLs are sometimes used to obscure malicious content, but length alone does not indicate a threat. Further analysis is recommended.")
            risk_counter += 1

        # Separate the domain name first
        domain_url = cleaned_url.replace("https://", "").replace("http://", "")
        domain = domain_url.split("/")[0]

        # Hyphen Counter
        hyphen_count = domain.count("-")
        if hyphen_count >= 2:
            print("Multiple hyphens detected in the domain. This pattern is commonly observed in phishing URLs and increases the risk score.")
            risk_counter += 1

        # IP address Detection

        def ipaddress(domain):
            parts = domain.split(".")
            if len(parts) != 4:
                return False
            for partnum in parts:
                if not partnum.isdigit():
                    return False

                number = int(partnum)
                if number < 0 or number > 255:
                    return False
            return True

        is_ipaddress = ipaddress(domain)

        if is_ipaddress is True:
            print("This URL uses a raw IP address instead of a domain name. URLs that rely on IP addresses are commonly associated with phishing or malicious activity, especially when used to bypass domain-based trust.")
            risk_counter += 2

        # Suspicious Keyword Detection
        wordlist = ["login", "verify", "secure", "update",
                    "account", "confirm", "reset", "payment", "support"]
        counter = 0
        for words in wordlist:
            if words in cleaned_url:
                counter += 1
        if counter >= 1:
            print("Suspicious keywords detected in the URL. Phishing links often use urgency or trust related terms such as login, verify, or update to manipulate users.")
            risk_counter += 1

        # Risk Counter
        print("\nFinal Risk Score:", risk_counter)

        if risk_counter == 0:
            print("Risk Level: Low. No common phishing indicators detected.")
        elif risk_counter <= 2:
            print(
                "Risk Level: Medium. Some suspicious patterns detected. Caution advised.")
        else:
            print(
                "Risk Level: High. Multiple phishing indicators detected. Avoid interacting with this URL.")

    # TOOL 2: Password Strength Checker
    elif option == 2:
        print("\n[ Password Strength Checker Selected ]\n")

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

    # EXIT
    elif option == 3:
        print("\nExiting toolkit. Stay safe online.")
        break

    # INVALID OPTION
    else:
        print("Invalid option. Please select 1, 2, or 3.")
