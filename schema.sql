-- SecureChat Database Schema

-- Drop database if exists (optional, for clean setup)
DROP DATABASE IF EXISTS securechat;

-- Create database
CREATE DATABASE securechat;

-- Use the database
USE securechat;

-- Create users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Verify table creation
SHOW TABLES;
DESCRIBE users;
