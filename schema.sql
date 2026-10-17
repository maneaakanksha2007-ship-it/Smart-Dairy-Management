
CREATE DATABASE smart_dairy;
USE smart_dairy;
SHOW DATABASES;

USE smart_dairy;

CREATE TABLE FARMER (
    Farmer_ID INT AUTO_INCREMENT PRIMARY KEY,
    Farmer_Name VARCHAR(100) NOT NULL,
    Aadhaar_No VARCHAR(20) UNIQUE,
    Mobile_No VARCHAR(15),
    Email_Address VARCHAR(120),
    Address VARCHAR(255),
    Bank_Account_No VARCHAR(40),
    IFSC_Code VARCHAR(20),
    Cattle_Type VARCHAR(50),
    RFID_No VARCHAR(50) NOT NULL UNIQUE,
    Password_Hash VARCHAR(255) NOT NULL,
    Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

SHOW TABLES;

DESCRIBE FARMER;

CREATE TABLE MILK_RECORD (
    Milk_Record_ID INT AUTO_INCREMENT PRIMARY KEY,
    Farmer_ID INT NOT NULL,
    Collection_Date DATE NOT NULL,
    Collection_Time TIME NOT NULL,
    RFID_No VARCHAR(50) NOT NULL,
    Quantity DECIMAL(8,2) NOT NULL,
    Fat DECIMAL(5,2) NOT NULL,
    SNF DECIMAL(5,2) NOT NULL,
    Rate_Per_Litre DECIMAL(8,2) NOT NULL,
    Total_Amount DECIMAL(10,2) NOT NULL,

    FOREIGN KEY (Farmer_ID)
        REFERENCES FARMER(Farmer_ID),

    CHECK (Quantity > 0),
    CHECK (Fat >= 0 AND Fat <= 100),
    CHECK (SNF >= 0 AND SNF <= 100),
    CHECK (Rate_Per_Litre >= 0),
    CHECK (Total_Amount >= 0)
);

DESCRIBE MILK_RECORD;

CREATE TABLE PAYMENT (
    Payment_ID INT AUTO_INCREMENT PRIMARY KEY,
    Farmer_ID INT NOT NULL,
    Payment_Date DATE NOT NULL,
    Quantity DECIMAL(10,2) NOT NULL DEFAULT 0,
    Total_Amount DECIMAL(10,2) NOT NULL,
    Payment_Status ENUM(
        'Pending',
        'Paid'
    ) NOT NULL DEFAULT 'Pending',

    FOREIGN KEY (Farmer_ID)
        REFERENCES FARMER(Farmer_ID),

    CHECK (Quantity >= 0),
    CHECK (Total_Amount >= 0)
);

CREATE TABLE BANK (
    Bank_ID INT AUTO_INCREMENT PRIMARY KEY,
    Bank_Name VARCHAR(100) NOT NULL,
    IFSC_Code VARCHAR(20) NOT NULL UNIQUE,
    Branch VARCHAR(100)
);

DESCRIBE BANK;

USE smart_dairy;

SHOW TABLES;