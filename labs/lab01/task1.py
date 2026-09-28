import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER

PASSWORDS = [
    "InfoS3c@2023",
    "simple123",
    "Def3ns3@Key",
    "public",
    "Encrypt3d#Pass",
    "basic123",
    "Secur3@Analysis",
    "temp123",
    "Pr0t3ct@Data",
    "default",
]

CRITERIA = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {"simple123", "public", "basic123", "temp123", "default", "guest"}


def simulate_password_reuse(passwords: list, sample_size: int = 3) -> list:

    extended = list(passwords)
    random_indexes = [random.randrange(len(passwords)) for _ in range(sample_size)]
    for index in random_indexes:
        extended.append(passwords[index])
    return extended


def _password_traits(password: str) -> dict:
   
    return {
        "has_digit": any(char.isdigit() for char in password),
        "has_upper": any(char.isupper() for char in password),
        "has_lower": any(char.islower() for char in password),
        "has_special": any(not char.isalnum() for char in password),
    }


def classify_password(password: str, all_passwords: list, criteria: dict, forbidden: set) -> str:
   
    min_length = criteria["min_length"]
    is_long_enough = len(password) >= min_length

    if password in forbidden or not is_long_enough:
        return "Forbidden"

    traits = _password_traits(password)
    required_groups = [traits["has_digit"], traits["has_upper"], traits["has_special"]]
    satisfied_required = sum(required_groups)
    meets_all_required = satisfied_required == len(required_groups)

    if meets_all_required:
        is_unique = all_passwords.count(password) == 1
        is_extra_long = len(password) >= min_length + 4
        if is_extra_long and is_unique:
            return "Very Strong"
        return "Strong"

    if satisfied_required >= 1:
        return "Medium"

    if traits["has_lower"]:
        return "Weak"

    return "Weak"


def print_report(rows: list) -> None:
    header = f"{'#':<3}{'Password':<20}{'Level':<15}"
    print(header)
    print("-" * len(header))
    for index, (password, level) in enumerate(rows, start=1):
        print(f"{index:<3}{password:<20}{level:<15}")


def main() -> None:
   
    print(f"Variant: {VARIANT_NUMBER}")
    print("Task1\n")

    extended_passwords = simulate_password_reuse(PASSWORDS, sample_size=3)

    results = [
        (password, classify_password(password, extended_passwords, CRITERIA, FORBIDDEN_PASSWORDS))
        for password in extended_passwords
    ]

    print_report(results)


if __name__ == "__main__":
    main()
