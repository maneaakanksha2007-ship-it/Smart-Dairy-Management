
import os
import mysql.connector
from dotenv import load_dotenv

# Load database settings from the .env file
load_dotenv()


def get_db_connection():
    """
    Create and return a connection to the Smart Dairy MySQL database.
    """

    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME", "smart_dairy")
    )

    return connection
