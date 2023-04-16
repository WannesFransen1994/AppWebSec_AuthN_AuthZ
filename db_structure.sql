CREATE DATABASE IF NOT EXISTS authlab;
USE authlab;

CREATE TABLE IF NOT EXISTS users(
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    UNIQUE KEY unique_email (email)
);