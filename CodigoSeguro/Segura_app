from flask import Flask, request, render_template_string, session, redirect, url_for, abort, jsonify, make_response
import sqlite3
import os
import bcrypt
import secrets
import re
from datetime import datetime, timedelta
from markupsafe import escape
import logging
from functools import wraps
from typing import Optional, Dict, Any
import html
import json

# Configuración de logging para seguridad
logging.basicConfig(
    filename='security.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuración de seguridad mejorada
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_SECURE=True,  # Solo enviar cookies sobre HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # No accesible desde JavaScript
    SESSION_COOKIE_SAMESITE='Lax',  # Protección CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Sesión expira en 30 minutos
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # Límite de tamaño de request: 16MB
)

# Configurar CSP (Content Security Policy)
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com; style-src 'self' 'unsafe-inline' https://maxcdn.bootstrapcdn.com;"
    return response

def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hashing seguro de contraseñas usando bcrypt con salt"""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    """Verificar contraseña de manera segura"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

def validate_input(data: str, max_length: int = 1000, pattern: Optional[str] = None) -> bool:
    """Validación de entrada con longitud y patrón"""
    if not data or len(data) > max_length:
        return False
    if pattern and not re.match(pattern, data):
        return False
    return True

def sanitize_html(content: str) -> str:
    """Sanitizar contenido HTML de manera segura"""
    # Escapar caracteres especiales HTML
    return html.escape(content)

def log_security_event(event_type: str, user_id: Optional[int] = None, username: str = "", details: str = ""):
    """Registrar eventos de seguridad en la base de datos"""
    try:
        conn = get_db_connection()
        ip_address = request.remote_addr if request else "Unknown"
        conn.execute('''
            INSERT INTO security_logs (event_type, user_id, username, ip_address, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (event_type, user_id, username, ip_address, details))
        conn.commit()
        conn.close()
        logger.warning(f"{event_type} - User: {username or 'anonymous'} - IP: {ip_address} - Details: {details}")
    except Exception as e:
        logger.error(f"Error logging security event: {str(e)}")

def login_required(f):
    """Decorador para verificar autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            log_security_event('UNAUTHORIZED_ACCESS', username=session.get('username', 'unknown'))
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorador para verificar rol de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            log_security_event('ADMIN_ACCESS_DENIED', user_id=session.get('user_id'), 
                             username=session.get('username', 'unknown'))
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token():
    """Generar token CSRF seguro"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

@app.context_processor
def inject_csrf_token():
    """Inyectar token CSRF en todas las plantillas"""
    return {'csrf_token': generate_csrf_token}

def validate_csrf_token(token: str) -> bool:
    """Validar token CSRF de manera segura"""
    if not token or '_csrf_token' not in session:
        return False
    return secrets.compare_digest(token, session['_csrf_token'])

@app.route('/')
def index():
    """Página principal con información de seguridad"""
    return render_template_string('''
        <!doctype html>
        <html lang="es">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>SecureApp - Bienvenido</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">¡Bienvenido a SecureApp!</h1>
                <p class="lead">Esta es una aplicación segura con todas las vulnerabilidades corregidas.</p>
                <div class="alert alert-info">
                    <h5>Características de Seguridad Implementadas:</h5>
                    <ul>
                        <li>Protección contra Inyección SQL (consultas parametrizadas)</li>
                        <li>Protección contra XSS (sanitización de entrada/salida)</li>
                        <li>Protección CSRF (tokens en formularios)</li>
                        <li>Hash de contraseñas con bcrypt (salt + múltiples rounds)</li>
                        <li>Headers de seguridad (CSP, HSTS, etc.)</li>
                        <li>Control de sesiones seguras (HTTPS-only, HttpOnly)</li>
                        <li>Rate limiting para prevenir ataques de fuerza bruta</li>
                        <li>Logging de eventos de seguridad</li>
                    </ul>
                </div>
                <p><a href="/login" class="btn btn-primary">Iniciar Sesión</a></p>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login seguro con protección contra ataques de fuerza bruta y SQL injection"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        csrf_token = request.form.get('csrf_token', '')
        
        # Validar token CSRF
        if not validate_csrf_token(csrf_token):
            log_security_event('CSRF_ATTEMPT', username=username)
            return render_template_string('''
                <!doctype html>
                <html lang="es">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login - SecureApp</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger" role="alert">Error de seguridad: Token CSRF inválido.</div>
                        <a href="/login" class="btn btn-primary">Intentar de nuevo</a>
                    </div>
                </body>
                </html>
            ''')
        
        # Validar entrada
        if not validate_input(username, max_length=50) or not validate_input(password, max_length=100):
            log_security_event('INVALID_INPUT', username=username)
            return render_template_string('''
                <!doctype html>
                <html lang="es">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login - SecureApp</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger" role="alert">Entrada inválida. Por favor, verifica tus datos.</div>
                        <a href="/login" class="btn btn-primary">Intentar de nuevo</a>
                    </div>
                </body>
                </html>
            ''')
        
        try:
            conn = get_db_connection()
            
            # Consulta parametrizada para prevenir SQL injection
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", 
                (username,)
            ).fetchone()
            
            # Verificar si la cuenta está bloqueada
            if user and user['locked_until']:
                lock_time = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < lock_time:
                    remaining = (lock_time - datetime.now()).seconds // 60
                    return render_template_string('''
                        <!doctype html>
                        <html lang="es">
                        <head>
                            <meta charset="utf-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                            <title>Login - SecureApp</title>
                        </head>
                        <body>
                            <div class="container">
                                <h1 class="mt-5">Login</h1>
                                <div class="alert alert-danger" role="alert">Cuenta bloqueada por {{ remaining }} minutos por intentos fallidos.</div>
                                <a href="/login" class="btn btn-primary">Intentar de nuevo</a>
                            </div>
                        </body>
                        </html>
                    ''', remaining=remaining)
            
            # Verificar contraseña
            if user and check_password(password, user['password']):
                # Login exitoso - Resetear intentos fallidos
                conn.execute(
                    "UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE id = ?",
                    (user['id'],)
                )
                conn.commit()
                
                # Crear sesión segura
                session.clear()
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session.permanent = True
                
                log_security_event('LOGIN_SUCCESS', user_id=user['id'], username=user['username'])
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                # Login fallido - Registrar intento
                if user:
                    login_attempts = user['login_attempts'] + 1
                    locked_until = None
                    
                    # Bloquear cuenta después de 5 intentos fallidos
                    if login_attempts >= 5:
                        locked_until = (datetime.now() + timedelta(minutes=15)).isoformat()
                        log_security_event('ACCOUNT_LOCKED', user_id=user['id'], 
                                         username=user['username'], details=f"Intento #{login_attempts}")
                    
                    conn.execute(
                        "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
                        (login_attempts, locked_until, user['id'])
                    )
                    conn.commit()
                    
                    log_security_event('LOGIN_FAILED', user_id=user['id'], 
                                     username=user['username'], details=f"Intento #{login_attempts}")
                else:
                    log_security_event('LOGIN_FAILED', username=username, details="Usuario no encontrado")
                
                conn.close()
                
                # Mostrar mensaje genérico de error (no revelar si el usuario existe o no)
                return render_template_string('''
                    <!doctype html>
                    <html lang="es">
                    <head>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                        <title>Login - SecureApp</title>
                    </head>
                    <body>
                        <div class="container">
                            <h1 class="mt-5">Login</h1>
                            <div class="alert alert-danger" role="alert">Credenciales inválidas. Por favor, intenta de nuevo.</div>
                            <a href="/login" class="btn btn-primary">Intentar de nuevo</a>
                        </div>
                    </body>
                    </html>
                ''')
                
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            log_security_event('LOGIN_ERROR', username=username, details=str(e))
            return render_template_string('''
                <!doctype html>
                <html lang="es">
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                    <title>Login - SecureApp</title>
                </head>
                <body>
                    <div class="container">
                        <h1 class="mt-5">Login</h1>
                        <div class="alert alert-danger" role="alert">Error al procesar el login. Por favor, intenta de nuevo.</div>
                        <a href="/login" class="btn btn-primary">Intentar de nuevo</a>
                    </div>
                </body>
                </html>
            ''')
    
    # GET request - Mostrar formulario de login
    return render_template_string('''
        <!doctype html>
        <html lang="es">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
            <title>Login - SecureApp</title>
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Login</h1>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div class="form-group">
                        <label for="username">Usuario</label>
                        <input type="text" class="form-control" id="username" name="username" required minlength="3" maxlength="50" pattern="^[a-zA-Z0-9_]+$">
                        <small class="form-text text-muted">Solo letras, números y guión bajo.</small>
                    </div>
                    <div class="form-group">
                        <label for="password">Contraseña</label>
                        <input type="password" class="form-control" id="password" name="password" required minlength="8" maxlength="100">
                        <small class="form-text text-muted">Mínimo 8 caracteres.</small>
                    </div>
                    <button type="submit" class="btn btn-primary">Iniciar Sesión</button>
                    <a href="/" class="btn btn-secondary">Volver</a>
                </form>
                <div class="mt-3">
                    <p><strong>Usuarios de prueba:</strong></p>
                    <ul>
                        <li>admin / SecureAdmin123!</li>
                        <li>user / SecureUser123!</li>
                        <li>guest / Guest123!</li>
                    </ul>
                </div>
            </div>
        </body>
        </html>
    ''')

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard del usuario con comentarios sanitizados"""
    try:
        user_id = session['user_id']
        conn = get_db_connection()
        
        # Obtener datos del usuario
        user = conn.execute(
            "SELECT username, role FROM users WHERE id = ?", 
            (user_id,)
        ).fetchone()
        
        # Obtener comentarios del usuario (todos los comentarios para admin)
        if session.get('role') == 'admin':
            comments = conn.execute(
                "SELECT c.comment, u.username, c.created_at FROM comments c "
                "JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC"
            ).fetchall()
        else:
            comments = conn.execute(
                "SELECT comment, created_at FROM comments WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            ).fetchall()
        
        conn.close()
        
        return render_template_string('''
            <!doctype html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                <title>Dashboard - SecureApp</title>
            </head>
            <body>
                <div class="container">
                    <nav class="navbar navbar-expand-lg navbar-light bg-light mt-3">
                        <a class="navbar-brand" href="#">SecureApp</a>
                        <div class="navbar-nav ml-auto">
                            <span class="navbar-text mr-3">
                                <strong>{{ username }}</strong> ({{ role }})
                            </span>
                            <a href="/logout" class="btn btn-outline-danger btn-sm">Cerrar Sesión</a>
                        </div>
                    </nav>
                    
                    <h1 class="mt-4">Panel de Control</h1>
                    
                    <div class="row mt-4">
                        <div class="col-md-8">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Agregar Comentario</h5>
                                </div>
                                <div class="card-body">
                                    <form action="/submit_comment" method="post">
                                        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                        <div class="form-group">
                                            <label for="comment">Comentario</label>
                                            <textarea class="form-control" id="comment" name="comment" rows="3" required maxlength="1000"></textarea>
                                            <small class="form-text text-muted">Máximo 1000 caracteres. El HTML será sanitizado automáticamente.</small>
                                        </div>
                                        <button type="submit" class="btn btn-primary">Enviar Comentario</button>
                                    </form>
                                </div>
                            </div>
                            
                            <div class="card mt-4">
                                <div class="card-header">
                                    <h5>Tus Comentarios</h5>
                                </div>
                                <div class="card-body">
                                    {% if comments %}
                                        <ul class="list-group">
                                            {% for comment in comments %}
                                                <li class="list-group-item">
                                                    {% if session.role == 'admin' %}
                                                        <strong>{{ comment.username }}</strong> - 
                                                        <small class="text-muted">{{ comment.created_at }}</small><br>
                                                    {% else %}
                                                        <small class="text-muted">{{ comment.created_at }}</small><br>
                                                    {% endif %}
                                                    {{ comment.comment | safe }}
                                                </li>
                                            {% endfor %}
                                        </ul>
                                    {% else %}
                                        <p class="text-muted">No tienes comentarios aún.</p>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-4">
                            <div class="card">
                                <div class="card-header">
                                    <h5>Información de Seguridad</h5>
                                </div>
                                <div class="card-body">
                                    <ul class="list-unstyled">
                                        <li><span class="text-success">✓</span> Sesión segura (HTTPS)</li>
                                        <li><span class="text-success">✓</span> Protección CSRF</li>
                                        <li><span class="text-success">✓</span> Sanitización de entrada</li>
                                        <li><span class="text-success">✓</span> Hash de contraseñas bcrypt</li>
                                    </ul>
                                </div>
                            </div>
                            
                            {% if session.role == 'admin' %}
                            <div class="card mt-4">
                                <div class="card-header">
                                    <h5>Panel de Administrador</h5>
                                </div>
                                <div class="card-body">
                                    <a href="/admin" class="btn btn-danger btn-block">Panel de Administración</a>
                                    <a href="/security_logs" class="btn btn-info btn-block mt-2">Logs de Seguridad</a>
                                </div>
                            </div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''', username=user['username'], role=user['role'], comments=comments)
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return "Error al cargar el dashboard", 500

@app.route('/submit_comment', methods=['POST'])
@login_required
def submit_comment():
    """Enviar comentario con sanitización y protección CSRF"""
    try:
        # Validar token CSRF
        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            log_security_event('CSRF_ATTEMPT', user_id=session.get('user_id'), 
                             username=session.get('username', 'unknown'))
            return "Token CSRF inválido", 403
        
        comment = request.form.get('comment', '').strip()
        
        # Validar entrada
        if not comment:
            return "El comentario no puede estar vacío", 400
        
        if len(comment) > 1000:
            return "El comentario es demasiado largo (máximo 1000 caracteres)", 400
        
        # Sanitizar comentario (prevenir XSS)
        sanitized_comment = sanitize_html(comment)
        
        user_id = session['user_id']
        
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO comments (user_id, comment) VALUES (?, ?)",
            (user_id, sanitized_comment)
        )
        conn.commit()
        conn.close()
        
        log_security_event('COMMENT_ADDED', user_id=user_id, 
                         username=session.get('username', 'unknown'), 
                         details=f"Comentario de {len(comment)} caracteres")
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Submit comment error: {str(e)}")
        return "Error al guardar el comentario", 500

@app.route('/admin')
@admin_required
def admin_panel():
    """Panel de administración seguro"""
    try:
        conn = get_db_connection()
        
        # Estadísticas de seguridad
        total_users = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()['count']
        total_comments = conn.execute("SELECT COUNT(*) as count FROM comments").fetchone()['count']
        recent_logins = conn.execute(
            "SELECT COUNT(*) as count FROM users WHERE last_login > datetime('now', '-1 day')"
        ).fetchone()['count']
        
        # Lista de usuarios
        users = conn.execute(
            "SELECT id, username, role, created_at, last_login, login_attempts, locked_until FROM users"
        ).fetchall()
        
        conn.close()
        
        return render_template_string('''
            <!doctype html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                <title>Admin Panel - SecureApp</title>
            </head>
            <body>
                <div class="container">
                    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mt-3">
                        <a class="navbar-brand" href="#">SecureApp Admin</a>
                        <div class="navbar-nav ml-auto">
                            <span class="navbar-text text-white mr-3">
                                <strong>{{ session.username }}</strong> (Admin)
                            </span>
                            <a href="/dashboard" class="btn btn-outline-light btn-sm mr-2">Dashboard</a>
                            <a href="/logout" class="btn btn-danger btn-sm">Cerrar Sesión</a>
                        </div>
                    </nav>
                    
                    <h1 class="mt-4">Panel de Administración</h1>
                    
                    <div class="row mt-4">
                        <div class="col-md-4">
                            <div class="card text-white bg-primary">
                                <div class="card-body">
                                    <h5 class="card-title">Total Usuarios</h5>
                                    <h2>{{ total_users }}</h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card text-white bg-success">
                                <div class="card-body">
                                    <h5 class="card-title">Total Comentarios</h5>
                                    <h2>{{ total_comments }}</h2>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="card text-white bg-info">
                                <div class="card-body">
                                    <h5 class="card-title">Logins Último Día</h5>
                                    <h2>{{ recent_logins }}</h2>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card mt-4">
                        <div class="card-header">
                            <h5>Gestión de Usuarios</h5>
                        </div>
                        <div class="card-body">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Usuario</th>
                                        <th>Rol</th>
                                        <th>Creado</th>
                                        <th>Último Login</th>
                                        <th>Intentos Fallidos</th>
                                        <th>Estado</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for user in users %}
                                        <tr>
                                            <td>{{ user.id }}</td>
                                            <td>{{ user.username }}</td>
                                            <td>
                                                <span class="badge badge-{{ 'danger' if user.role == 'admin' else 'info' if user.role == 'user' else 'secondary' }}">
                                                    {{ user.role }}
                                                </span>
                                            </td>
                                            <td>{{ user.created_at }}</td>
                                            <td>{{ user.last_login or 'Nunca' }}</td>
                                            <td>{{ user.login_attempts }}</td>
                                            <td>
                                                {% if user.locked_until %}
                                                    <span class="badge badge-danger">Bloqueado</span>
                                                {% else %}
                                                    <span class="badge badge-success">Activo</span>
                                                {% endif %}
                                            </td>
                                        </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    
                    <div class="card mt-4">
                        <div class="card-header">
                            <h5>Configuración de Seguridad</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Protecciones Activadas:</h6>
                                    <ul>
                                        <li>✓ Inyección SQL prevenida (parametrización)</li>
                                        <li>✓ XSS prevenido (sanitización)</li>
                                        <li>✓ CSRF protegido (tokens)</li>
                                        <li>✓ Contraseñas seguras (bcrypt)</li>
                                        <li>✓ Sessions seguras (HTTPS, HttpOnly)</li>
                                        <li>✓ Headers de seguridad (CSP, HSTS)</li>
                                    </ul>
                                </div>
                                <div class="col-md-6">
                                    <h6>Acciones Administrativas:</h6>
                                    <div class="btn-group-vertical w-100">
                                        <a href="/security_logs" class="btn btn-info">Ver Logs de Seguridad</a>
                                        <a href="/logout" class="btn btn-danger mt-2">Cerrar Sesión</a>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </body>
            </html>
        ''', total_users=total_users, total_comments=total_comments, recent_logins=recent_logins, users=users)
        
    except Exception as e:
        logger.error(f"Admin panel error: {str(e)}")
        return "Error al cargar el panel de administración", 500

@app.route('/security_logs')
@admin_required
def security_logs():
    """Ver logs de seguridad (solo administradores)"""
    try:
        conn = get_db_connection()
        logs = conn.execute('''
            SELECT * FROM security_logs 
            ORDER BY created_at DESC 
            LIMIT 100
        ''').fetchall()
        conn.close()
        
        return render_template_string('''
            <!doctype html>
            <html lang="es">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet">
                <title>Logs de Seguridad - SecureApp</title>
                <style>
                    .log-entry {
                        font-family: monospace;
                        font-size: 12px;
                    }
                    .log-critical { border-left: 4px solid #dc3545; }
                    .log-warning { border-left: 4px solid #ffc107; }
                    .log-info { border-left: 4px solid #17a2b8; }
                </style>
            </head>
            <body>
                <div class="container">
                    <nav class="navbar navbar-expand-lg navbar-dark bg-dark mt-3">
                        <a class="navbar-brand" href="#">Logs de Seguridad</a>
                        <div class="navbar-nav ml-auto">
                            <a href="/admin" class="btn btn-outline-light btn-sm mr-2">Admin</a>
                            <a href="/dashboard" class="btn btn-outline-light btn-sm mr-2">Dashboard</a>
                            <a href="/logout" class="btn btn-danger btn-sm">Cerrar Sesión</a>
                        </div>
                    </nav>
                    
                    <h1 class="mt-4">Registro de Eventos de Seguridad</h1>
                    
                    <div class="card mt-3">
                        <div class="card-body">
                            {% if logs %}
                                <div class="list-group">
                                    {% for log in logs %}
                                        <div class="list-group-item log-entry 
                                            {% if 'LOGIN_SUCCESS' in log.event_type %}log-info
                                            {% elif 'FAILED' in log.event_type or 'ATTEMPT' in log.event_type %}log-warning
                                            {% elif 'LOCKED' in log.event_type or 'ERROR' in log.event_type
