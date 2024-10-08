# from fastapi import FastAPI, Depends, HTTPException, status
# from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, ALL
# from pydantic import BaseModel
# from jose import JWTError, jwt
# from datetime import datetime, timedelta
# from typing import Optional

# # Configuraciones
# SECRET_KEY = "your_secret_key"
# ALGORITHM = "HS256"
# ACCESS_TOKEN_EXPIRE_MINUTES = 30

# # Clase para recibir las credenciales
# class UserCredentials(BaseModel):
#     username: str
#     password: str

# # Inicializar la aplicación FastAPI
# app = FastAPI()

# # Función para autenticar con LDAP (Active Directory)
# def authenticate_user(username: str, password: str):
#     try:
#         # Dirección del servidor LDAP (cambiar por el tuyo)
#         ldap_server = Server('ldap://192.168.0.15', get_info=ALL)
#         # Conexión con el servidor LDAP
#         conn = Connection(
#             ldap_server, 
#             user=f'DTPHS\\{username}',  # Nombre de usuario
#             password=password,  # Contraseña del usuario
#             auto_bind=AUTO_BIND_NO_TLS
#         )
#         return True  # Si la autenticación es exitosa
#     except Exception as e:
#         print(f"Error de autenticación: {e}")
#         return False  # Si falla la autenticación

# # Función para crear un token JWT
# def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
#     to_encode = data.copy()
#     if expires_delta:
#         expire = datetime.utcnow() + expires_delta
#     else:
#         expire = datetime.utcnow() + timedelta(minutes=15)
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
#     return encoded_jwt

# # Ruta de autenticación
# @app.post("/token")
# async def login(user_credentials: UserCredentials):
#     username = user_credentials.username
#     password = user_credentials.password
#     if authenticate_user(username, password):
#         access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
#         access_token = create_access_token(
#             data={"sub": username}, expires_delta=access_token_expires
#         )
#         return {"access_token": access_token, "token_type": "bearer"}
#     else:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Incorrect username or password",
#             headers={"WWW-Authenticate": "Bearer"},
#         )

# # Ruta protegida que requiere autenticación
# @app.get("/users/me")
# async def read_users_me(token: str = Depends(create_access_token)):
#     try:
#         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
#         username: str = payload.get("sub")
#         if username is None:
#             raise HTTPException(status_code=401, detail="Could not validate credentials")
#         return {"username": username}
#     except JWTError:
#         raise HTTPException(status_code=401, detail="Could not validate credentials")
from fastapi import FastAPI, HTTPException, Depends, status, Request
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from typing import List
from pydantic import BaseModel
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Configuración del servidor LDAP
LDAP_SERVER = 'ldap://192.168.0.15'
SECRET_KEY = "your_secret_key"  # Cambia por una clave secreta más segura
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Grupo de administradores
ADMIN_GROUP_DN = 'CN=Administradores,CN=Builtin,DC=DTPHS,DC=LOCAL'

# Simulación de una "sesión" para almacenar las conexiones por usuario (temporal, no en producción)
sessions = {}

app = FastAPI()

# Modelo de autenticación
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    password: str | None = None

# Modelo de login
class LoginModel(BaseModel):
    username: str
    password: str

# Modelo para crear usuario
class UserCreateModel(BaseModel):
    fullname: str
    username: str
    password: str

# Modelo de respuesta para listar usuarios
class UserResponseModel(BaseModel):
    fullname: str
    username: str
    status: str

# Función para conectar al servidor LDAP
def get_ldap_connection(username: str, password: str):
    LDAP_USERNAME = f'{username}@DTPHS.LOCAL'
    
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, user=LDAP_USERNAME, password=password, auto_bind=True)
        return conn
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error connecting to LDAP: {e}")

# Función para autenticar al usuario contra LDAP
def authenticate_user(username: str, password: str):
    conn = get_ldap_connection(username, password)
    if not conn.bind():
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return conn

# Función para verificar si el usuario pertenece al grupo de administradores
def is_user_in_admin_group(username: str, conn: Connection):
    search_filter = f'(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))'
    conn.search(
        search_base='DC=DTPHS,DC=LOCAL',
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['memberOf']
    )

    if len(conn.entries) == 0:
        raise HTTPException(status_code=404, detail="User not found")

    entry = conn.entries[0]
    
    if hasattr(entry, 'memberOf'):
        member_of = entry.memberOf.values
        return ADMIN_GROUP_DN in member_of

    return False

# Generar JWT con username y password
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependencia para obtener el usuario actual a partir del token
async def get_current_user(request: Request):
    authorization: str = request.headers.get("Authorization")
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ")[1]
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        password: str = payload.get("password")
        if username is None or password is None:
            raise credentials_exception
        return TokenData(username=username, password=password)
    except JWTError:
        raise credentials_exception

# Ruta para hacer login y generar token
@app.post("/login", response_model=Token)
async def login(form_data: LoginModel):
    # Autenticar usuario con LDAP
    conn = authenticate_user(form_data.username, form_data.password)
    if not conn:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Crear token que almacena username y password
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username, "password": form_data.password}, expires_delta=access_token_expires
    )
    
    # Almacenar la conexión en la "sesión"
    sessions[form_data.username] = conn

    return {"access_token": access_token, "token_type": "bearer"}

# Ruta para obtener todos los usuarios (sin necesidad de reenviar token)
@app.get("/users", response_model=List[UserResponseModel])
async def read_users(current_user: TokenData = Depends(get_current_user)):
    # Recuperar la conexión almacenada en la "sesión"
    conn = sessions.get(current_user.username)
    
    if not conn:
        raise HTTPException(status_code=401, detail="User session not found")

    if not is_user_in_admin_group(current_user.username, conn):
        raise HTTPException(status_code=403, detail="Access denied: User is not in the Administrators group")

    users = get_all_users(conn)
    return users

# Ruta para crear un usuario (sin necesidad de reenviar token)
# Ruta para crear un usuario (sin necesidad de reenviar token)
@app.post("/createuser")
async def create_user(user: UserCreateModel, current_user: TokenData = Depends(get_current_user)):
    # Usar la conexión almacenada en la "sesión"
    conn = sessions.get(current_user.username)
    
    if not conn:
        raise HTTPException(status_code=401, detail="User session not found")

    if not is_user_in_admin_group(current_user.username, conn):
        raise HTTPException(status_code=403, detail="Access denied: User is not in the Administrators group")

    user_dn = f"CN={user.fullname},OU=usuariosapp,DC=DTPHS,DC=LOCAL"
    user_attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': user.fullname,
        'sAMAccountName': user.username,
        'userPrincipalName': f"{user.username}@dtphs.local",  # Se agrega userPrincipalName
        'displayName': user.fullname,
        'givenName': user.fullname.split()[0],
        'sn': user.fullname.split()[-1],
        'userAccountControl': '544'  # La cuenta está deshabilitada hasta que se asigne la contraseña
    }
    
    try:
        # Crear el usuario en el AD
        conn.add(dn=user_dn, attributes=user_attributes)
        
        if not conn.result['description'] == 'success':
            raise HTTPException(status_code=500, detail=f"Error creating user: {conn.result['description']}")
        
        # Habilitar la cuenta después de la creación
        conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
        
        # Verificar si la cuenta ha sido habilitada
        conn.search(user_dn, '(objectClass=user)', attributes=['userAccountControl'])
        if len(conn.entries) == 0:
            raise HTTPException(status_code=404, detail="User not found after creation")
        
        user_account_control = int(conn.entries[0].userAccountControl.value)
        if (user_account_control & 2) != 0:  # Si el bit 2 está activado, la cuenta sigue deshabilitada
            raise HTTPException(status_code=500, detail="Failed to unlock the account")

        # Asignar la contraseña
        password_utf16 = f'"{user.password}"'.encode('utf-16-le')
        conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [password_utf16])]})
        print(password_utf16)
        
        return {"message": f"User {user.fullname} created and password set successfully", "password": user.password}  # Se incluye la contraseña en la respuesta

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {e}")




# Función para obtener todos los usuarios del dominio
def get_all_users(conn: Connection):
    search_filter = '(&(objectClass=user)(objectCategory=person))'
    conn.search(
        search_base='DC=DTPHS,DC=LOCAL',
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=['cn', 'sAMAccountName', 'userAccountControl']
    )

    users = []
    for entry in conn.entries:
        user_account_control = int(entry.userAccountControl.value)
        account_status = 'Disabled' if (user_account_control & 2) != 0 else 'Enabled'
        users.append({
            'fullname': entry.cn.value,
            'username': entry.sAMAccountName.value,
            'status': account_status
        })

    return users
