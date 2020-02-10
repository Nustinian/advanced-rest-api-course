import os

from typing import List
from requests import Response, post

FAILED_TO_LOAD = "Failed to load {}."
EMAIL_ERROR = "Error in sending the account activation email, user registration failed."


class MailgunException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class Mailgun:
    MAILGUN_DOMAIN = os.environ.get("MAILGUN_DOMAIN")
    MAILGUN_API_KEY = os.environ.get("MAILGUN_API_KEY")

    FROM_TITLE = "Austin Mailgun"
    FROM_EMAIL = "postmaster@sandboxfdabe9034bb647e9bd02a43609ebe4c5.mailgun.org"

    @classmethod
    def send_email(
        cls, email: List[str], subject: str, text: str, html: str
    ) -> Response:
        if cls.MAILGUN_API_KEY is None:
            raise MailgunException(FAILED_TO_LOAD.format("Mailgun API key"))
        if cls.MAILGUN_DOMAIN is None:
            raise MailgunException(FAILED_TO_LOAD.format("Mailgun domain"))

        response = post(
            f"https://api.mailgun.net/v3/{cls.MAILGUN_DOMAIN}/messages",
            auth=("api", cls.MAILGUN_API_KEY),
            data={
                "from": f"{cls.FROM_TITLE} <{cls.FROM_EMAIL}>",
                "to": email,
                "subject": subject,
                "text": text,
                "html": html,
            },
        )

        if response.status_code != 200:
            raise MailgunException(EMAIL_ERROR)

        return response

