"""GraphQL context for request handling.

VULNERABILITY G05: Authentication is optional and not enforced on resolvers.
"""

from typing import Optional
from strawberry.fastapi import BaseContext
from fastapi import Request
from jose import jwt, JWTError

from app.config import settings
from app.models import User


class GraphQLContext(BaseContext):
    """
    Custom context for GraphQL requests.

    VULNERABILITY G05: Auth is extracted but not enforced.
    Resolvers can access user but don't have to check it.
    """

    def __init__(self, request: Request):
        self.request = request
        self._current_user: Optional[User] = None
        self._user_loaded = False

    @property
    def current_user(self) -> Optional[User]:
        """
        Get the current user from JWT token.

        VULNERABILITY: Returns None instead of raising error if not authenticated.
        This allows unauthenticated access to protected resources.
        """
        if self._user_loaded:
            return self._current_user

        self._user_loaded = True
        auth_header = self.request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return None

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm]
            )
            # Store user info from token
            self._current_user = type('User', (), {
                'id': payload.get('user_id'),
                'username': payload.get('sub'),
                'role': payload.get('role'),
            })()
            return self._current_user
        except JWTError:
            return None

    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return self.current_user is not None

    @property
    def is_admin(self) -> bool:
        """Check if user is admin."""
        user = self.current_user
        return user is not None and user.role in ('admin', 'superadmin')


async def get_context(request: Request) -> GraphQLContext:
    """Create GraphQL context from request."""
    return GraphQLContext(request)
