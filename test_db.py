
from db import get_db_connection

connection = None

try:
    connection = get_db_connection()

    if connection.is_connected():
        print("SUCCESS: Connected to MySQL!")

        cursor = connection.cursor()
        cursor.execute("SELECT DATABASE()")
        result = cursor.fetchone()

        print("Connected database:", result[0])
        cursor.close()

except Exception as error:
    print("ERROR: Could not connect to MySQL.")
    print(error)

finally:
    if connection is not None and connection.is_connected():
        connection.close()
