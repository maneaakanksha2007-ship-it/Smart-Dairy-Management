
import os
import logging
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from dotenv import load_dotenv
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from mysql.connector import IntegrityError

from db import get_db_connection

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False  # Use True with HTTPS in production
)


# Prevent browsers from displaying stale protected pages.
@app.after_request
def prevent_page_caching(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ----------------------------------
# ROLE-BASED ACCESS CONTROL
# ----------------------------------

def login_required(role):
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                if session.get("role") == "admin":
                    return redirect(url_for("admin_dashboard"))
                if session.get("role") == "farmer":
                    return redirect(url_for("farmer_dashboard"))

                if role == "admin":
                    return redirect(url_for("admin_login"))
                return redirect(url_for("farmer_login"))

            return view_function(*args, **kwargs)
        return wrapper
    return decorator


def dashboard_for_current_user():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    if session.get("role") == "farmer":
        return redirect(url_for("farmer_dashboard"))
    return None


# ----------------------------------
# HOME PAGE
# ----------------------------------

@app.route("/")
def home():
    destination = dashboard_for_current_user()
    if destination:
        return destination
    return render_template("index.html")


# ----------------------------------
# FARMER REGISTRATION
# ----------------------------------

@app.route("/farmer-register", methods=["GET", "POST"])
def farmer_register():
    destination = dashboard_for_current_user()
    if destination:
        return destination

    if request.method == "POST":
        name = request.form.get("farmer_name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        address = request.form.get("address", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not mobile or not address:
            flash("Please complete all required fields.")
            return render_template("farmer_register.html")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return render_template("farmer_register.html")

        if password != confirm_password:
            flash("Passwords do not match.")
            return render_template("farmer_register.html")

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                """
                INSERT INTO FARMER
                    (Farmer_Name, Mobile_No, Address,
                     RFID_No, Password_Hash, Registration_Status)
                VALUES (%s, %s, %s, NULL, %s, 'Pending')
                """,
                (
                    name, mobile, address,
                    generate_password_hash(password)
                )
            )

            connection.commit()
            flash(
                "Registration successful. You can check your "
                "RFID status using your mobile number and password."
            )
            return redirect(url_for("check_rfid"))

        except Exception:
            if connection and connection.is_connected():
                connection.rollback()
            app.logger.exception("Farmer registration failed")
            flash("Registration failed. Please try again.")

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    return render_template("farmer_register.html")


# ----------------------------------
# CHECK ASSIGNED RFID
# ----------------------------------

@app.route("/check-rfid", methods=["GET", "POST"])
def check_rfid():
    destination = dashboard_for_current_user()
    if destination:
        return destination

    result = None

    if request.method == "POST":
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")

        if not mobile or not password:
            flash("Enter your mobile number and password.")
            return render_template("rfid_lookup.html", result=None)

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            # Multiple records are checked safely if mobile numbers
            # are not unique in an older database.
            cursor.execute(
                """
                SELECT Farmer_Name, Mobile_No, RFID_No,
                       Password_Hash, Registration_Status
                FROM FARMER
                WHERE Mobile_No = %s
                """,
                (mobile,)
            )

            farmers = cursor.fetchall()

            farmer = next(
                (
                    item for item in farmers
                    if check_password_hash(
                        item["Password_Hash"], password
                    )
                ),
                None
            )

            if farmer:
                result = {
                    "name": farmer["Farmer_Name"],
                    "status": farmer["Registration_Status"],
                    "rfid": farmer["RFID_No"]
                }
            else:
                flash("Invalid mobile number or password.")

        except Exception:
            app.logger.exception("RFID lookup failed")
            flash("Unable to check RFID status. Please try again.")

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    return render_template("rfid_lookup.html", result=result)


# ----------------------------------
# FARMER LOGIN: RFID + PASSWORD
# ----------------------------------

@app.route("/farmer-login", methods=["GET", "POST"])
def farmer_login():
    destination = dashboard_for_current_user()
    if destination:
        return destination

    if request.method == "POST":
        rfid = request.form.get("rfid", "").strip()
        password = request.form.get("password", "")

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT Farmer_ID, Farmer_Name, RFID_No, Password_Hash
                FROM FARMER
                WHERE RFID_No = %s
                  AND Registration_Status = 'Approved'
                """,
                (rfid,)
            )

            farmer = cursor.fetchone()

            if farmer and check_password_hash(
                farmer["Password_Hash"], password
            ):
                session.clear()
                session["role"] = "farmer"
                session["farmer_id"] = farmer["Farmer_ID"]
                session["farmer_name"] = farmer["Farmer_Name"]
                session["rfid_no"] = farmer["RFID_No"]

                return redirect(url_for("farmer_dashboard"))

            flash(
                "Invalid RFID or password, or your account "
                "has not been approved."
            )

        except Exception:
            app.logger.exception("Farmer login failed")
            flash("Unable to log in. Please try again.")

        finally:
            if cursor:
                cursor.close()
            if connection and connection.is_connected():
                connection.close()

    return render_template("farmer_login.html")


# ----------------------------------
# ADMIN LOGIN
# ----------------------------------

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    destination = dashboard_for_current_user()
    if destination:
        return destination

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if (
            username == os.getenv("ADMIN_USERNAME")
            and password == os.getenv("ADMIN_PASSWORD")
            and os.getenv("ADMIN_USERNAME")
            and os.getenv("ADMIN_PASSWORD")
        ):
            session.clear()
            session["role"] = "admin"
            session["admin_username"] = username
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin username or password.")

    return render_template("admin_login.html")


# ----------------------------------
# FARMER DASHBOARD
# ----------------------------------

@app.route("/farmer-dashboard")
@login_required("farmer")
def farmer_dashboard():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        farmer_id = session["farmer_id"]

        cursor.execute(
            """
            SELECT Milk_Record_ID, Collection_Date, Collection_Time,
                   Quantity, Fat, SNF, Rate_Per_Litre, Total_Amount
            FROM MILK_RECORD
            WHERE Farmer_ID = %s
            ORDER BY Collection_Date DESC, Collection_Time DESC
            """,
            (farmer_id,)
        )
        milk_records = cursor.fetchall()

        cursor.execute(
            """
            SELECT Payment_ID, Payment_Date, Amount_Paid, Payment_Status
            FROM PAYMENT
            WHERE Farmer_ID = %s
            ORDER BY Payment_Date DESC, Payment_ID DESC
            """,
            (farmer_id,)
        )
        payments = cursor.fetchall()

        return render_template(
            "farmer_dashboard.html",
            farmer_name=session["farmer_name"],
            farmer_rfid=session["rfid_no"],
            milk_records=milk_records,
            payments=payments
        )

    except Exception:
        app.logger.exception("Farmer dashboard failed")
        flash("Unable to load your dashboard.")
        return redirect(url_for("farmer_login"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ----------------------------------
# ADMIN DASHBOARD
# ----------------------------------

@app.route("/admin-dashboard")
@login_required("admin")
def admin_dashboard():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM FARMER")
        farmer_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM MILK_RECORD")
        milk_count = cursor.fetchone()[0]

        cursor.execute(
            """
            SELECT COUNT(*) FROM PAYMENT
            WHERE Payment_Status = 'Pending'
            """
        )
        pending_payment_count = cursor.fetchone()[0]

        return render_template(
            "admin_dashboard.html",
            farmer_count=farmer_count,
            milk_count=milk_count,
            pending_payment_count=pending_payment_count
        )

    except Exception:
        app.logger.exception("Admin dashboard failed")
        flash("Unable to load admin dashboard.")
        return redirect(url_for("admin_login"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ----------------------------------
# ADMIN: PENDING FARMERS
# ----------------------------------

@app.route("/admin/pending-farmers")
@login_required("admin")
def pending_farmers():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT Farmer_ID, Farmer_Name, Mobile_No, Address
            FROM FARMER
            WHERE Registration_Status = 'Pending'
              AND RFID_No IS NULL
            ORDER BY Farmer_ID DESC
            """
        )

        return render_template(
            "pending_farmers.html",
            farmers=cursor.fetchall()
        )

    except Exception:
        app.logger.exception("Pending farmers page failed")
        flash("Unable to load pending registrations.")
        return redirect(url_for("admin_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()


# ----------------------------------
# ADMIN: ASSIGN RFID
# ----------------------------------

@app.route(
    "/admin/approve-farmer/<int:farmer_id>",
    methods=["POST"]
)
@login_required("admin")
def approve_farmer(farmer_id):
    rfid = request.form.get("rfid", "").strip()

    if not rfid or len(rfid) > 50:
        flash("Enter a valid RFID number (1–50 characters).")
        return redirect(url_for("pending_farmers"))

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE FARMER
            SET RFID_No = %s, Registration_Status = 'Approved'
            WHERE Farmer_ID = %s
              AND Registration_Status = 'Pending'
              AND RFID_No IS NULL
            """,
            (rfid, farmer_id)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            flash("Farmer was already processed or does not exist.")
        else:
            connection.commit()
            flash("Farmer approved and RFID saved successfully.")

    except IntegrityError:
        if connection and connection.is_connected():
            connection.rollback()
        flash("That RFID is already assigned. Enter a different one.")

    except Exception:
        if connection and connection.is_connected():
            connection.rollback()
        app.logger.exception("RFID assignment failed")
        flash("Unable to assign RFID.")

    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()

    return redirect(url_for("pending_farmers"))


# ----------------------------------
# LOGOUT
# ----------------------------------

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


# ---------------- PHASE 5: MILK COLLECTION ----------------

from datetime import date, datetime
from decimal import Decimal, InvalidOperation


@app.route("/milk-collection", methods=["GET", "POST"])
@login_required("admin")
def milk_collection():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            rfid = request.form.get("rfid", "").strip()
            collection_date = request.form.get("collection_date", "")
            collection_time = request.form.get("collection_time", "")
            quantity_text = request.form.get("quantity", "")
            fat_text = request.form.get("fat", "")
            snf_text = request.form.get("snf", "")
            rate_text = request.form.get("rate", "")

            try:
                quantity = Decimal(quantity_text)
                fat = Decimal(fat_text)
                snf = Decimal(snf_text)
                rate = Decimal(rate_text)

                if not all(x.is_finite() for x in [quantity, fat, snf, rate]):
                    raise InvalidOperation

                if quantity <= 0 or rate < 0:
                    raise InvalidOperation

                if not (0 <= fat <= 100 and 0 <= snf <= 100):
                    raise InvalidOperation

                if len(quantity.as_tuple().digits) > 8:
                    raise InvalidOperation

                if len(rate.as_tuple().digits) > 8:
                    raise InvalidOperation

                if len(fat.as_tuple().digits) > 5 or len(snf.as_tuple().digits) > 5:
                    raise InvalidOperation

                datetime.strptime(collection_date, "%Y-%m-%d")
                datetime.strptime(collection_time, "%H:%M")

            except (InvalidOperation, ValueError):
                flash("Enter valid collection details.", "error")
                return redirect(url_for("milk_collection"))

            cursor.execute(
                """
                SELECT Farmer_ID
                FROM FARMER
                WHERE RFID_No = %s
                  AND Registration_Status = 'Approved'
                """,
                (rfid,)
            )
            farmer = cursor.fetchone()

            if not farmer:
                flash("RFID not found or farmer is not approved.", "error")
                return redirect(url_for("milk_collection"))

            total_amount = (quantity * rate).quantize(Decimal("0.01"))

            cursor.execute(
                """
                INSERT INTO MILK_RECORD
                (Farmer_ID, Collection_Date, Collection_Time, RFID_No,
                 Quantity, Fat, SNF, Rate_Per_Litre, Total_Amount)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    farmer["Farmer_ID"], collection_date, collection_time,
                    rfid, quantity, fat, snf, rate, total_amount
                )
            )
            connection.commit()
            flash("Milk collection saved successfully.", "success")
            return redirect(url_for("milk_records"))

        cursor.execute(
            """
            SELECT Farmer_ID, Farmer_Name, RFID_No
            FROM FARMER
            WHERE Registration_Status = 'Approved'
              AND RFID_No IS NOT NULL
            ORDER BY Farmer_Name
            """
        )
        farmers = cursor.fetchall()

        return render_template(
            "milk_collection.html",
            farmers=farmers,
            today=date.today().isoformat(),
            current_time=datetime.now().strftime("%H:%M")
        )
    finally:
        cursor.close()
        connection.close()


# ---------------- MILK RECORDS ----------------

@app.route("/milk-records")
@login_required("admin")
def milk_records():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT m.*, f.Farmer_Name
            FROM MILK_RECORD m
            JOIN FARMER f ON f.Farmer_ID = m.Farmer_ID
            ORDER BY m.Collection_Date DESC, m.Collection_Time DESC
            """
        )
        records = cursor.fetchall()
        return render_template("milk_records.html", records=records)
    finally:
        cursor.close()
        connection.close()


# ---------------- FARMER'S OWN MILK RECORDS ----------------

@app.route("/farmer-records")
@login_required("farmer")
def farmer_records():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM MILK_RECORD
            WHERE Farmer_ID = %s
            ORDER BY Collection_Date DESC, Collection_Time DESC
            """,
            (session["farmer_id"],)
        )
        records = cursor.fetchall()
        return render_template("farmer_records.html", records=records)
    finally:
        cursor.close()
        connection.close()


# ---------------- PAYMENT MANAGEMENT ----------------

def get_farmer_payment_summary(cursor, farmer_id=None):
    """Return bill, actual paid amount, and outstanding balance per farmer."""
    params = []
    farmer_filter = ""
    if farmer_id is not None:
        farmer_filter = "WHERE f.Farmer_ID = %s"
        params.append(farmer_id)

    cursor.execute(
        f"""
        SELECT
            f.Farmer_ID,
            f.Farmer_Name,
            f.RFID_No,
            COALESCE(m.total_bill, 0.00) AS Total_Bill,
            COALESCE(p.total_paid, 0.00) AS Total_Paid
        FROM FARMER f
        LEFT JOIN (
            SELECT Farmer_ID, SUM(Total_Amount) AS total_bill
            FROM MILK_RECORD
            GROUP BY Farmer_ID
        ) m ON m.Farmer_ID = f.Farmer_ID
        LEFT JOIN (
            SELECT Farmer_ID, SUM(Amount_Paid) AS total_paid
            FROM PAYMENT
            WHERE Payment_Status = 'Paid'
            GROUP BY Farmer_ID
        ) p ON p.Farmer_ID = f.Farmer_ID
        {farmer_filter}
        ORDER BY f.Farmer_Name
        """,
        tuple(params)
    )
    summaries = cursor.fetchall()
    for row in summaries:
        bill = Decimal(str(row["Total_Bill"] or "0.00"))
        paid = Decimal(str(row["Total_Paid"] or "0.00"))
        row["Total_Bill"] = bill.quantize(Decimal("0.01"))
        row["Total_Paid"] = paid.quantize(Decimal("0.01"))
        row["Outstanding"] = max(
            row["Total_Bill"] - row["Total_Paid"],
            Decimal("0.00")
        )
    return summaries




@app.route("/admin/farmer-balance/<int:farmer_id>")
@login_required("admin")
def farmer_balance(farmer_id):
    """AJAX endpoint: return current bill, paid total, and outstanding amount."""
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT Farmer_ID, Farmer_Name
            FROM FARMER
            WHERE Farmer_ID = %s
              AND Registration_Status = 'Approved'
            """,
            (farmer_id,)
        )
        farmer = cursor.fetchone()
        if not farmer:
            return jsonify({"error": "Approved farmer not found."}), 404

        cursor.execute(
            """
            SELECT COALESCE(SUM(Total_Amount), 0.00) AS Total_Bill
            FROM MILK_RECORD
            WHERE Farmer_ID = %s
            """,
            (farmer_id,)
        )
        total_bill = Decimal(str(cursor.fetchone()["Total_Bill"] or "0.00"))

        cursor.execute(
            """
            SELECT COALESCE(SUM(Amount_Paid), 0.00) AS Total_Paid
            FROM PAYMENT
            WHERE Farmer_ID = %s AND Payment_Status = 'Paid'
            """,
            (farmer_id,)
        )
        total_paid = Decimal(str(cursor.fetchone()["Total_Paid"] or "0.00"))
        outstanding = max(total_bill - total_paid, Decimal("0.00"))

        return jsonify({
            "farmer_name": farmer["Farmer_Name"],
            "total_bill": f"{total_bill:.2f}",
            "total_paid": f"{total_paid:.2f}",
            "outstanding": f"{outstanding:.2f}"
        })
    except Exception:
        app.logger.exception("Could not retrieve farmer balance")
        return jsonify({"error": "Unable to load farmer balance."}), 500
    finally:
        if cursor:
            cursor.close()
        if connection and connection.is_connected():
            connection.close()



@app.route("/payments", methods=["GET", "POST"])
@login_required("admin")
def payments():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        if request.method == "POST":
            farmer_id_text = request.form.get("farmer_id", "").strip()
            amount_text = request.form.get("amount_paid", "").strip()
            payment_date = request.form.get("payment_date", "").strip()

            try:
                farmer_id = int(farmer_id_text)
                amount = Decimal(amount_text)
                datetime.strptime(payment_date, "%Y-%m-%d")

                if not amount.is_finite() or amount <= 0:
                    raise InvalidOperation
                if amount.as_tuple().exponent < -2:
                    raise InvalidOperation
                if amount > Decimal("99999999.99"):
                    raise InvalidOperation
            except (ValueError, InvalidOperation):
                flash("Enter a valid farmer, payment amount, and date.", "error")
                return redirect(url_for("payments"))

            # Lock the farmer row while checking the balance and recording
            # a payment so two requests cannot pay the same balance at once.
            connection.start_transaction()
            cursor.execute(
                """
                SELECT Farmer_ID
                FROM FARMER
                WHERE Farmer_ID = %s
                  AND Registration_Status = 'Approved'
                FOR UPDATE
                """,
                (farmer_id,)
            )
            farmer = cursor.fetchone()
            if not farmer:
                connection.rollback()
                flash("Select a valid approved farmer.", "error")
                return redirect(url_for("payments"))

            cursor.execute(
                """
                SELECT COALESCE(SUM(Total_Amount), 0.00) AS Total_Bill
                FROM MILK_RECORD
                WHERE Farmer_ID = %s
                """,
                (farmer_id,)
            )
            total_bill = Decimal(str(cursor.fetchone()["Total_Bill"] or "0.00"))

            cursor.execute(
                """
                SELECT COALESCE(SUM(Amount_Paid), 0.00) AS Total_Paid
                FROM PAYMENT
                WHERE Farmer_ID = %s AND Payment_Status = 'Paid'
                """,
                (farmer_id,)
            )
            total_paid = Decimal(str(cursor.fetchone()["Total_Paid"] or "0.00"))
            outstanding = max(total_bill - total_paid, Decimal("0.00"))

            if outstanding <= 0:
                connection.rollback()
                flash("This farmer has no outstanding balance.", "error")
                return redirect(url_for("payments"))

            if amount > outstanding:
                connection.rollback()
                flash(
                    f"Payment exceeds the outstanding balance of ₹{outstanding:.2f}.",
                    "error"
                )
                return redirect(url_for("payments"))

            cursor.execute(
                """
                INSERT INTO PAYMENT
                    (Farmer_ID, Payment_Date, Amount_Paid, Payment_Status)
                VALUES (%s, %s, %s, 'Paid')
                """,
                (farmer_id, payment_date, amount)
            )
            connection.commit()
            flash("Actual payment recorded successfully.", "success")
            return redirect(url_for("payments"))

        cursor.execute(
            """
            SELECT Farmer_ID, Farmer_Name, RFID_No
            FROM FARMER
            WHERE Registration_Status = 'Approved'
            ORDER BY Farmer_Name
            """
        )
        farmers = cursor.fetchall()

        summaries = get_farmer_payment_summary(cursor)

        cursor.execute(
            """
            SELECT p.Payment_ID, p.Farmer_ID, p.Payment_Date,
                   p.Amount_Paid, p.Payment_Status, f.Farmer_Name
            FROM PAYMENT p
            JOIN FARMER f ON f.Farmer_ID = p.Farmer_ID
            ORDER BY p.Payment_Date DESC, p.Payment_ID DESC
            """
        )
        payment_records = cursor.fetchall()

        return render_template(
            "payments.html",
            is_admin=True,
            farmers=farmers,
            summaries=summaries,
            payment_records=payment_records,
            today=date.today().isoformat()
        )
    except Exception:
        if connection and connection.is_connected():
            connection.rollback()
        app.logger.exception("Payment page failed")
        flash("Unable to load or save payment information.", "error")
        return redirect(url_for("admin_dashboard"))
    finally:
        cursor.close()
        connection.close()


# ---------------- FARMER'S OWN PAYMENTS ----------------

@app.route("/farmer-payments")
@login_required("farmer")
def farmer_payments():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        farmer_id = session["farmer_id"]
        summaries = get_farmer_payment_summary(cursor, farmer_id)

        cursor.execute(
            """
            SELECT Payment_ID, Payment_Date, Amount_Paid, Payment_Status
            FROM PAYMENT
            WHERE Farmer_ID = %s
            ORDER BY Payment_Date DESC, Payment_ID DESC
            """,
            (farmer_id,)
        )
        payment_records = cursor.fetchall()

        return render_template(
            "payments.html",
            is_admin=False,
            farmers=[],
            summaries=summaries,
            payment_records=payment_records,
            today=date.today().isoformat()
        )
    except Exception:
        app.logger.exception("Farmer payment history failed")
        flash("Unable to load your payment history.", "error")
        return redirect(url_for("farmer_dashboard"))
    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    app.run(debug=True)
