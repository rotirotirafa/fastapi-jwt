import jwt

from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext


class AuthHandler:
    security = HTTPBearer()
    password_context = CryptContext(schemes=['bcrypt'], deprecated="auto")
    secret = 'SECRET'

    def get_password_hash(self, password):
        return self.password_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        return self.password_context.verify(plain_password, hashed_password)

    def encode_token(self, user_id):
        payload = {
            # TODO verificar tempo de expiração
            'sub': user_id
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature Expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    def auth_wrapper(self, auth: HTTPAuthorizationCredentials = Security(security)):
        return self.decode_token(auth.credentials)

