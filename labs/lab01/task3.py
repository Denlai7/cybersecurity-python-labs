import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 9

PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

USERS_TO_REGISTER = (
    ("red_team_lead", "AttackChain#2024"),
    ("blue_team_analyst", "MonitorSOC!2024"),
    ("purple_team_coord", "BridgeTeams@2024"),
    ("student_intern", "LearnCyber#99"),
    ("green_dev_ops", "PipelineSafe!24"),
    ("soc_watcher_01", "AlertTriage#88"),
    ("forensics_lead", "EvidenceChain@1"),
    ("threat_hunter_x", "HuntThreats#7Z"),
    ("compliance_rep", "AuditReady!2024"),
    ("vuln_scanner_op", "ScanDaily#Secure"),
)


class ValidationError(Exception):
    """Oh no there is a validation error. Change something"""

def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Salt and password cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )

    hasher = hashlib.blake2s()
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


def create_user(username: str, password: str) -> tuple:
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        for username, password in users_list:
            try:
                record = create_user(username, password)
                writer.writerow(record)
            except (ValueError, ValidationError) as error:
                print(f"Missing user '{username}': {error}")


def read_users_db() -> list:
    users_db = []
    with open(USERS_CSV_PATH, mode="r", newline="", encoding="utf-8") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if row:
                users_db.append(tuple(row))
    return users_db


def print_users_table(users_db: list) -> None:
    header = f"{'Username':<20}{'Password hash':<70}"
    print(header)
    print("-" * len(header))
    for username, hash_value in users_db:
        print(f"{username:<20}{hash_value:<70}")


def log_event(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        username = args[0] if args else kwargs.get("username", "unknown")
        result = "failure"
        try:
            success = func(*args, **kwargs)
            result = "success" if success else "failure"
            return success
        finally:
            entry = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": timestamp,
                "args": list(args[1:]) if len(args) > 1 else [],
                "kwargs": {},
            }
            _append_log_entry(entry)

    return wrapper


def _append_log_entry(entry: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    events = []
    if os.path.exists(LOG_JSON_PATH):
        try:
            with open(LOG_JSON_PATH, mode="r", encoding="utf-8") as log_file:
                events = json.load(log_file)
        except (OSError, json.JSONDecodeError):
            events = []

    events.append(entry)

    with open(LOG_JSON_PATH, mode="w", encoding="utf-8") as log_file:
        json.dump(events, log_file, indent=2, ensure_ascii=False)


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Username and password cannot be empty")

    users_db = read_users_db()
    users_by_name = dict(users_db)

    if username not in users_by_name:
        return False

    candidate_hash = generate_hash(password, PERSONAL_SALT)
    return candidate_hash == users_by_name[username]


def main() -> None:
    print("Task3\n")

    try:
        create_users(USERS_TO_REGISTER)
        print(f"Registered users in {USERS_CSV_PATH}\n")

        users_db = read_users_db()
        print_users_table(users_db)
        print()

        first_username, first_password = USERS_TO_REGISTER[0]
        print(f"Trying to log in '{first_username}' with the correct password:")
        print("  Result:", login(first_username, first_password))
        print(f"Trying to log in '{first_username}' with the wrong password:")
        print("  Result:", login(first_username, "WrongPassword123"))

    except FileNotFoundError as error:
        print(f"File not found: {error}")
    except PermissionError as error:
        print(f"Permission denied: {error}")
    except OSError as error:
        print(f"Input/Output error: {error}")
    except ValidationError as error:
        print(f"Validation error: {error}")
    except ValueError as error:
        print(f"Invalid value: {error}")


if __name__ == "__main__":
    main()
