import sqlite3
import hashlib
import os
import logging

DATABASE_NAME = "gscapy_user_data.db"

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def create_tables():
    """Creates the necessary tables in the database if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # User table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Security questions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        answer_hash TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    # Pre-defined security questions (for reference in the application)
    # This list will be used by the registration UI.
    SECURITY_QUESTIONS_LIST = [
        "What was your first pet's name?",
        "What is your mother's maiden name?",
        "What was the name of your elementary school?",
        "What city were you born in?",
        "What is your favorite book?",
        "What was the model of your first car?",
        "What is your favorite movie?",
        "What is your favorite food?",
        "What is the name of your best childhood friend?",
        "In what city did you meet your spouse/partner?",
        "What is your favorite sports team?",
        "What was your high school mascot?",
        "What is the name of the street you grew up on?",
        "What is your favorite color?",
        "What is your father's middle name?"
    ]


    # Test history table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS test_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        test_type TEXT NOT NULL,
        target TEXT NOT NULL,
        results TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    """)

    conn.commit()
    conn.close()
    logging.info("Database tables created or already exist.")

def create_admin_user():
    """Creates the default admin user if it doesn't already exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the admin user already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", ('admin',))
    if cursor.fetchone():
        logging.info("Admin user already exists.")
        conn.close()
        return

    # If admin does not exist, create it
    admin_username = "admin"
    admin_password = "F@rh@dyan2281251462"
    admin_email = "admin@gscapy.local"
    hashed_password = hash_password(admin_password)

    cursor.execute("""
    INSERT INTO users (username, email, password_hash, is_admin, is_active)
    VALUES (?, ?, ?, 1, 1)
    """, (admin_username, admin_email, hashed_password))

    conn.commit()
    conn.close()
    logging.info("Default admin user created successfully.")

def verify_user(username, password):
    """Verifies user credentials against the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    hashed_password = hash_password(password)

    cursor.execute("""
        SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1
    """, (username, hashed_password))

    user = cursor.fetchone()
    conn.close()
    return user

def check_username_or_email_exists(username, email):
    """Checks if a username or email already exists in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
    exists = cursor.fetchone()

    conn.close()
    return exists is not None

def create_user(username, email, password):
    """Creates a new user in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    hashed_password = hash_password(password)

    cursor.execute("""
        INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)
    """, (username, email, hashed_password))

    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id

def add_security_questions(user_id, questions_with_answers):
    """Adds security questions and their hashed answers for a user."""
    conn = get_db_connection()
    cursor = conn.cursor()

    for q_id, answer in questions_with_answers:
        hashed_answer = hash_password(answer.lower().strip())
        cursor.execute("""
            INSERT INTO security_questions (user_id, question_id, answer_hash)
            VALUES (?, ?, ?)
        """, (user_id, q_id, hashed_answer))

    conn.commit()
    conn.close()

def get_all_users():
    """Retrieves all users from the database for the admin panel."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, is_admin, is_active FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def set_user_active_status(user_id, is_active):
    """Updates the is_active status for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (int(is_active), user_id))
    conn.commit()
    conn.close()

def update_user_password(user_id, new_password):
    """Updates the password for a given user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(new_password)
    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
    conn.commit()
    conn.close()

def initialize_database():
    """
    Initializes the database: creates tables and the default admin user.
    This function should be called once when the application starts.
    """
    logging.info("Initializing database...")
    create_tables()
    create_admin_user()
    logging.info("Database initialization complete.")

if __name__ == '__main__':
    # This allows the script to be run directly to set up the database
    initialize_database()
    print(f"Database '{DATABASE_NAME}' initialized successfully.")
