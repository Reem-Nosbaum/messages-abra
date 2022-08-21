from repo import Repo


class RequestsValidation:

    def __init__(self, repo):
        self.repo: Repo = repo

    def create_new_user(self, username: str, password: str) -> bool:
        if self.repo.get_user_by_username(username=username):
            return False
        self.repo.create_new_user(username=username, password=password)
        return True
