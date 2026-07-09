import sqlite3
import bcrypt
import os
from datetime import datetime

# Conexión a la base de datos (se creará automáticamente si no existe)
conn = sqlite3.connect('example.db')

# Crear un cursor
c = conn.cursor()

# Crear la tabla de usuarios con campos adicionales para seguridad
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP
    )
''')

# Crear la tabla de comentarios
c.execute('''
    CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Crear tabla para tokens CSRF
c.execute('''
    CREATE TABLE IF NOT EXISTS csrf_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

# Crear tabla para logs de seguridad
c.execute('''
    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        ip_address TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Función para hash de contraseñas con bcrypt
def hash_password(password):
    salt = bcrypt.gensalt(rounds=12)  # 12 rounds es seguro y eficiente
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# Insertar usuarios de prueba con contraseñas seguras
users = [
    ('admin', hash_password('SecureAdmin123!'), 'admin'),
    ('user', hash_password('SecureUser123!'), 'user'),
    ('guest', hash_password('Guest123!'), 'guest')
]

for username, password, role in users:
    try:
        c.execute('''
            INSERT INTO users (username, password, role) VALUES (?, ?, ?)
        ''', (username, password, role))
    except sqlite3.IntegrityError:
        print(f"Usuario {username} ya existe, omitiendo...")

# Insertar comentarios de ejemplo
sample_comments = [
    (1, "Este es un comentario de ejemplo del admin."),
    (2, "Este es un comentario del usuario normal."),
    (3, "Comentario del usuario invitado.")
]

for user_id, comment in sample_comments:
    c.execute('''
        INSERT INTO comments (user_id, comment) VALUES (?, ?)
    ''', (user_id, comment))

# Guardar los cambios y cerrar la conexión
conn.commit()
conn.close()

print("Base de datos y tablas creadas con éxito.")
print("Usuarios creados:")
print("- admin / SecureAdmin123!")
print("- user / SecureUser123!")
print("- guest / Guest123!")
