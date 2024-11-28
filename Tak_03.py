import re

def check_password_complexity(password):
    # Define the complexity requirements
    length_requirement = len(password) >= 8
    uppercase_requirement = bool(re.search(r"[A-Z]", password))
    lowercase_requirement = bool(re.search(r"[a-z]", password))
    digit_requirement = bool(re.search(r"\d", password))
    special_char_requirement = bool(re.search(r"[!@#$%^&*()_+-=]", password))

    # Create a dictionary to store the status of each requirement
    requirements = {
        "Length (at least 8 characters)": length_requirement,
        "Uppercase letter": uppercase_requirement,
        "Lowercase letter": lowercase_requirement,
        "Digit": digit_requirement,
        "Special character (!@#$%^&*()_+-=)": special_char_requirement
    }

    # Check if all requirements are met
    if all(requirements.values()):
        print("Password is strong!")
    else:
        print("Password is weak. Please meet the following requirements:")
        for requirement, met in requirements.items():
            if not met:
                print(f"- {requirement}")

# Test the password complexity checker
password = input("Enter a password to check: ")
check_password_complexity(password)
