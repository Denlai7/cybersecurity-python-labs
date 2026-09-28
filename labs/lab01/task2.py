import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

USERS = {
    "red_team_lead": {
        "role": "red_team",
        "clearance": 4,
        "department": "Red Team",
        "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team",
        "clearance": 3,
        "department": "Blue Team",
        "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team",
        "clearance": 3,
        "department": "Purple Team",
        "active": True,
    },
    "student_intern": {
        "role": "student",
        "clearance": 1,
        "department": "Academia",
        "active": True,
    },
    "retired_expert": {
        "role": "retired",
        "clearance": 2,
        "department": "Emeritus",
        "active": False,
    },
}

RESOURCES = [
    ("attack_scenarios", 4),
    ("defense_playbooks", 3),
    ("exercise_plans", 3),
    ("research_papers", 1),
    ("exploit_tools", 4),
    ("student_resources", 1),
    ("simulation_results", 3),
    ("red_team_tools", 4),
    ("blue_team_reports", 3),
    ("public_research", 1),
]

SECURITY_LEVELS = ("Academic", "Operational", "Tactical", "Strategic")

BLOCKED_USERS = {"retired_expert", "academic_violator", "leaked_account"}


def level_name(level_number: int, security_levels: tuple) -> str:
   return security_levels[level_number - 1]


def print_resources(resources: list, security_levels: tuple) -> None:
    print("System Resources and Security Levels:")
    for name, level in resources:
        print(f"  - {name}: {level_name(level, security_levels)}")
    print()


def check_access(username: str, resource_level: int, users: dict, blocked: set) -> tuple:
    if username not in users:
        return False, "User not found"

    if username in blocked:
        return False, "User is blocked"

    user = users[username]

    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, None

    return False, "Insufficient clearance"


def run_access_checks(users: dict, resources: list, blocked: set) -> None:
    for username in users:
        for resource_name, resource_level in resources:
            allowed, reason = check_access(username, resource_level, users, blocked)
            decision = "ALLOW" if allowed else f"DENY ({reason})"
            print(f"user={username} resource={resource_name} -> {decision}")


def main() -> None:
    print("Task2\n")

    print_resources(RESOURCES, SECURITY_LEVELS)
    run_access_checks(USERS, RESOURCES, BLOCKED_USERS)


if __name__ == "__main__":
    main()
