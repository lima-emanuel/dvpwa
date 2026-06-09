import time
from unittest.mock import AsyncMock, Mock

import pytest

from sqli.dao.student import Student
from sqli.dao.user import User


@pytest.mark.asyncio
async def test_sqli_regression_student_create():
    """
    Regression test for SQL Injection in Student.create.
    Ensures that dynamic string interpolation is no longer used, and instead,
    the query uses parameterized statements.
    """
    # 1. Setup mock database connection
    conn = AsyncMock()
    cursor_mock = AsyncMock()

    # cursor_mock acts as the async context manager
    cursor_mock.__aenter__ = AsyncMock(return_value=cursor_mock)
    cursor_mock.__aexit__ = AsyncMock(return_value=False)

    # cursor() is synchronous in aiopg — use a regular Mock
    conn.cursor = Mock(return_value=cursor_mock)

    # 2. Execute the create method with a malicious payload
    malicious_payload = "Robert'); DROP TABLE students;--"
    await Student.create(conn, malicious_payload)

    # 3. Verify parameterization is used correctly
    assert cursor_mock.execute.called, "The execute method was never called."

    args, kwargs = cursor_mock.execute.call_args
    query = args[0]

    # The query string itself should NOT contain the payload (which would indicate string interpolation)
    assert malicious_payload not in query, (
        "SQL Injection vulnerability: Target payload was interpolated directly into the query string!"
    )

    # The payload MUST be passed safely in the parameters sequence (second argument to execute)
    assert len(args) > 1, (
        "Parameters sequence was not provided to execute(). Query is not parameterized."
    )
    parameters = args[1]
    assert (
        malicious_payload in parameters or malicious_payload in parameters.values()
    ), "Malicious payload was not safely passed via query parameters."


def test_crypto_regression_user_password():
    """
    Regression test for Weak Password Hashing in User.check_password.
    Ensures that MD5 is replaced by a secure hashing function and validates slow execution.
    """
    import bcrypt

    # 1. Provision a test user setup identically to the database
    password = "SuperSecretPassword123!"
    salt = bcrypt.gensalt(rounds=12)  # Use a realistic work factor
    secure_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

    user = User(
        id=1,
        first_name="Security",
        middle_name=None,
        last_name="Admin",
        username="secadmin",
        pwd_hash=secure_hash,
        is_admin=True,
    )

    # 2. Assert functional requirements (Success / Failure modes)
    assert user.check_password(password) is True, (
        "Password check failed for the correct password."
    )
    assert user.check_password("WrongPassword") is False, (
        "Password check incorrectly succeeded for a wrong password."
    )

    # 3. Assert Non-Functional requirements (Prevention of Brute/Rainbow attacks)
    # A secure hash (bcrypt/argon2/etc.) is intentionally slow. MD5 is nearly instantaneous.
    start_time = time.time()
    user.check_password("TimingTestPassword")
    duration = time.time() - start_time

    # Expect the check to take over 0.05s (50ms). MD5 would take < 0.001s
    assert duration > 0.05, (
        f"Password hash check was too fast ({duration:.4f}s). Are you still using MD5 or a non-KDF hashing algorithm?"
    )
