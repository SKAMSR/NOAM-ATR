import sqlite3

# יצירת חיבור לבסיס הנתונים
def get_db_connection():
    conn = sqlite3.connect('users.db')  # או נתיב אחר אם דרוש
    conn.row_factory = sqlite3.Row
    return conn

# פונקציה לאימות משתמש
def authenticate_user(email, password):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ? AND password = ?', (email, password)).fetchone()
    conn.close()
    return user is not None

# פונקציה להוספת משתמש
def add_user(email, password, is_admin):
    conn = get_db_connection()
    conn.execute('INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)', (email, password, is_admin))
    conn.commit()
    conn.close()

# פונקציה לאיפוס סיסמה
def reset_password(email, new_password):
    conn = get_db_connection()
    conn.execute('UPDATE users SET password = ? WHERE email = ?', (new_password, email))
    conn.commit()
    conn.close()
