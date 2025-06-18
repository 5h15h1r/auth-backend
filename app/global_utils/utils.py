import uuid    
import re
from typing import List

def get_uuid4():
        return str(uuid.uuid4())


def validate_password_rules(password: str) -> List[str]:
    errors = []

    if len(password) < 8:
        errors.append("Use at least 8 characters")

    if not re.search(r"[A-Z]", password):
        errors.append("Include at least one uppercase letter")

    if not re.search(r"[a-z]", password):
        errors.append("Include at least one lowercase letter")

    if not re.search(r"[0-9]", password):
        errors.append("Include at least one number")

    if not re.search(r"[!@#$%^&*()_\-+=\[\]{};:'\"\\|,.<>/?]", password):
        errors.append("Include at least one symbol (e.g., @, #, !)")

    return errors
