#!/usr/bin/env python3
"""
Database utilities for SecureChat user management
"""

import os
import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseManager:
    """Manages MySQL database connections and user operations"""
    
    def __init__(self):
        """Initialize database connection parameters from environment"""
        self.host = os.getenv('DB_HOST', 'localhost')
        self.user = os.getenv('DB_USER', 'root')
        self.password = os.getenv('DB_PASSWORD', '')
        self.database = os.getenv('DB_NAME', 'securechat')
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        try:
            self.connection = mysql.connector.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                database=self.database
            )
            if self.connection.is_connected():
                print("[✓] Connected to MySQL database")
                return True
        except Error as e:
            print(f"[!] Error connecting to MySQL: {e}")
            return False
    
    def disconnect(self):
        """Close database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[✓] Database connection closed")
    
    def user_exists(self, email=None, username=None):
        """
        Check if user exists by email or username
        
        Args:
            email: User email
            username: Username
        
        Returns:
            True if user exists, False otherwise
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            if email:
                query = "SELECT COUNT(*) FROM users WHERE email = %s"
                cursor.execute(query, (email,))
            elif username:
                query = "SELECT COUNT(*) FROM users WHERE username = %s"
                cursor.execute(query, (username,))
            else:
                return False
            
            result = cursor.fetchone()
            return result[0] > 0
            
        except Error as e:
            print(f"[!] Error checking user existence: {e}")
            return False
        finally:
            cursor.close()
    
    def register_user(self, email, username, salt, pwd_hash):
        """
        Register a new user in the database
        
        Args:
            email: User email (unique)
            username: Username (unique)
            salt: Random salt (16 bytes)
            pwd_hash: Salted password hash (64-char hex string)
        
        Returns:
            tuple: (success, message)
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
        
        # Check if user already exists
        if self.user_exists(email=email):
            return False, "Email already registered"
        
        if self.user_exists(username=username):
            return False, "Username already taken"
        
        cursor = self.connection.cursor()
        
        try:
            query = """
                INSERT INTO users (email, username, salt, pwd_hash)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (email, username, salt, pwd_hash))
            self.connection.commit()
            
            print(f"[✓] User registered: {username} ({email})")
            return True, "Registration successful"
            
        except Error as e:
            self.connection.rollback()
            print(f"[!] Error registering user: {e}")
            return False, f"Registration failed: {str(e)}"
        finally:
            cursor.close()
    
    def get_user_credentials(self, email):
        """
        Retrieve user's salt and password hash
        
        Args:
            email: User email
        
        Returns:
            tuple: (salt, pwd_hash) or (None, None) if user not found
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
        
        cursor = self.connection.cursor()
        
        try:
            query = "SELECT salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            
            if result:
                return result[0], result[1]
            else:
                return None, None
                
        except Error as e:
            print(f"[!] Error retrieving credentials: {e}")
            return None, None
        finally:
            cursor.close()
    
    def verify_login(self, email, pwd_hash):
        """
        Verify user login credentials
        
        Args:
            email: User email
            pwd_hash: Computed password hash
        
        Returns:
            tuple: (success, message)
        """
        stored_salt, stored_hash = self.get_user_credentials(email)
        
        if stored_salt is None:
            return False, "User not found"
        
        # Constant-time comparison (Python's == for strings is sufficient)
        if pwd_hash == stored_hash:
            print(f"[✓] Login successful for: {email}")
            return True, "Login successful"
        else:
            print(f"[!] Login failed for: {email}")
            return False, "Invalid credentials"
    
    def get_user_info(self, email):
        """
        Get user information
        
        Args:
            email: User email
        
        Returns:
            dict with user info or None
        """
        if not self.connection or not self.connection.is_connected():
            self.connect()
        
        cursor = self.connection.cursor(dictionary=True)
        
        try:
            query = "SELECT id, email, username, created_at FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            return result
            
        except Error as e:
            print(f"[!] Error retrieving user info: {e}")
            return None
        finally:
            cursor.close()

# Convenience functions
def get_db():
    """Get a database manager instance"""
    return DatabaseManager()
