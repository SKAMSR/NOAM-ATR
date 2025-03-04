import streamlit as st
import sqlite3
import pandas as pd
import bcrypt
from database import authenticate_user, add_user, reset_password

# חיבור למסד נתונים
def connect_db():
    conn = sqlite3.connect("users.db")
    return conn

# יצירת טבלה אם לא קיימת
def create_table():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        username TEXT,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        is_frozen INTEGER DEFAULT 0
    )''')
    conn.commit()
    conn.close()

# הוספת משתמש למסד הנתונים
def add_user_to_db(email, username, password, is_admin=False):
    conn = connect_db()
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute('INSERT INTO users (email, username, password, is_admin) VALUES (?, ?, ?, ?)',
                   (email, username, hashed_password, 1 if is_admin else 0))
    conn.commit()
    conn.close()

# אימות משתמש
def authenticate_user(email, password):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE email = ?', (email,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return bcrypt.checkpw(password.encode('utf-8'), row[0])
    return False

# עדכון נתוני משתמש
def edit_user_in_db(user_id, new_name, new_email, new_password=None, is_admin=False):
    conn = connect_db()
    cursor = conn.cursor()
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute('UPDATE users SET username = ?, email = ?, password = ?, is_admin = ? WHERE id = ?',
                       (new_name, new_email, hashed_password, 1 if is_admin else 0, user_id))
    else:
        cursor.execute('UPDATE users SET username = ?, email = ?, is_admin = ? WHERE id = ?',
                       (new_name, new_email, 1 if is_admin else 0, user_id))
    conn.commit()
    conn.close()

# מחיקת משתמש
def delete_user_from_db(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

# הקפאת משתמש
def freeze_user_in_db(user_id):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_frozen = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

# שליפת כל המשתמשים
def get_users_from_db():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    conn.close()
    return rows

# יצוא ל-Excel
def export_to_excel(df):
    return df.to_excel(index=False)

# יצירת ממשק ניהול
def admin_panel():
    st.title("ניהול משתמשים")

    # שליפת הנתונים מה-DB
    users = get_users_from_db()

    # המרת הנתונים לפורמט DataFrame (הסתרת סיסמאות)
    df = pd.DataFrame(users, columns=["ID", "מייל", "כינוי", "סיסמה", "מנהל", "הקפאה"])

    # הסתרת סיסמה
    df["סיסמה"] = "********"  # הסתרת הסיסמאות

    # הצגת טבלה עם אפשרויות עריכה, מחיקה והקפאה
    st.dataframe(df)

    # עריכת משתמש
    edit_index = st.number_input("בחר אינדקס לעריכה", min_value=0, max_value=len(df)-1)
    new_name = st.text_input("כינוי חדש", value=df.loc[edit_index, "כינוי"])
    new_email = st.text_input("אימייל חדש", value=df.loc[edit_index, "מייל"])
    is_admin = st.checkbox("האם מנהל?", value=bool(df.loc[edit_index, "מנהל"]))

    new_password = st.text_input("סיסמה חדשה (אם רוצים לשנות)", type="password")

    if st.button("ערוך נתונים"):
        user_id = df.loc[edit_index, "ID"]
        edit_user_in_db(user_id, new_name, new_email, new_password, is_admin)
        st.success("הנתונים עודכנו בהצלחה!")
        st.experimental_rerun()

    # מחיקת משתמש
    delete_index = st.number_input("בחר אינדקס למחיקה", min_value=0, max_value=len(df)-1)
    if st.button("מחק משתמש"):
        user_id = df.loc[delete_index, "ID"]
        delete_user_from_db(user_id)
        st.success("המשתמש נמחק בהצלחה!")
        st.experimental_rerun()

    # הקפאת משתמש
    freeze_index = st.number_input("בחר אינדקס להקפאה", min_value=0, max_value=len(df)-1)
    if st.button("הקפא משתמש"):
        user_id = df.loc[freeze_index, "ID"]
        freeze_user_in_db(user_id)
        st.success("המשתמש הוקפא בהצלחה!")
        st.experimental_rerun()

    # יצוא ל-Excel
    if st.button("יצא ל-Excel"):
        excel_file = export_to_excel(df)
        st.download_button(label="הורד את קובץ ה-Excel", data=excel_file, file_name="users.xlsx", mime="application/vnd.ms-excel")

def login_page():
    st.title("התחברות למערכת")
    email = st.text_input("אימייל")
    password = st.text_input("סיסמה", type="password")
    
    if st.button("התחבר"):
        if authenticate_user(email, password):
            st.session_state["logged_in"] = True
            st.session_state["email"] = email
            st.success("התחברת בהצלחה!")
            st.experimental_rerun()
        else:
            st.error("אימייל או סיסמה שגויים")

def main():
    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False
    
    if st.session_state["logged_in"]:
        st.sidebar.button("התנתק", on_click=lambda: st.session_state.update({"logged_in": False}))
        admin_panel()
    else:
        login_page()

if __name__ == "__main__":
    create_table()  # יצירת הטבלה אם היא לא קיימת
    main()
