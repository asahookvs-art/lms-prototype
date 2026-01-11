import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
import mysql.connector
import bcrypt
import random
import string
from datetime import date, timedelta
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

login_manager = LoginManager(app)
login_manager.login_view = "index"


class User(UserMixin):
    def __init__(self, db_id, role):
        self.db_id = db_id
        self.role = role

    def get_id(self):
        return f"{self.role}:{self.db_id}"


@login_manager.user_loader
def load_user(user_id):
    try:
        role, db_id = user_id.split(":", 1)
        db_id_int = int(db_id)
    except ValueError:
        return None

    db = connect()
    cur = db.cursor(dictionary=True)
    if role == "admin":
        cur.execute("SELECT id FROM admins WHERE id=%s", (db_id_int,))
    else:
        cur.execute("SELECT id FROM students WHERE id=%s", (db_id_int,))
    row = cur.fetchone()
    cur.close()
    db.close()
    if row:
        return User(db_id_int, role)
    return None


# ---- DATABASE SETUP ---- #


def connect():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )


def setup():
    try:
        # db = mysql.connector.connect(
        #     host=os.getenv("DB_HOST"),
        #     user=os.getenv("DB_USER"),
        #     password=os.getenv("DB_PASSWORD"),
        # )
        db = connect()
        cur = db.cursor(dictionary=True)
        # cur.execute("CREATE DATABASE IF NOT EXISTS lms_db")
        # cur.execute("USE lms_db")

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS admins(
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(100) UNIQUE,
            password VARCHAR(255)
        )"""
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS students(
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100),
            email VARCHAR(100) UNIQUE,
            password VARCHAR(255),
            reg_code VARCHAR(10),
            is_active INT DEFAULT 0
        )"""
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS books(
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(100),
            author VARCHAR(100),
            quantity INT
        )"""
        )

        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS issued_books(
            id INT AUTO_INCREMENT PRIMARY KEY,
            student_id INT,
            book_id INT,
            issue_date DATE,
            due_date DATE,
            return_date DATE,
            fine INT
        )"""
        )

        db.commit()

        # Create default admin if not exists
        cur.execute("SELECT * FROM admins WHERE email='admin@library.com'")
        if not cur.fetchone():
            pwd = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
            cur.execute(
                "INSERT INTO admins (email,password) VALUES (%s,%s)",
                ("admin@library.com", pwd),
            )
            db.commit()

        cur.close()
        db.close()
    except Exception as e:
        print("Setup Error:", e)


def gen_code():
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != "admin":
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)

    return decorated_function


def student_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != "student":
            return redirect(url_for("student_login"))
        return f(*args, **kwargs)

    return decorated_function


# ---- ROUTES ---- #


@app.route("/")
def index():
    return render_template("index.html")


# ---- ADMIN ROUTES ---- #


@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        pwd = request.form["password"]

        db = connect()
        cur = db.cursor(dictionary=True)
        cur.execute("SELECT id, password FROM admins WHERE email=%s", (email,))
        row = cur.fetchone()
        cur.close()
        db.close()

        if row and bcrypt.checkpw(
            pwd.encode(),
            (
                row["password"].encode()
                if isinstance(row["password"], str)
                else row["password"]
            ),
        ):
            login_user(User(row["id"], "admin"))
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin login", "error")

    return render_template("auth/admin_login.html")


@app.route("/admin-dashboard")
@admin_required
def admin_dashboard():
    return render_template("admin/admin_dashboard.html")


@app.route("/students")
@admin_required
def view_students():
    query = request.args.get("q", "").strip()
    db = connect()
    cur = db.cursor(dictionary=True)
    if query:
        if query.isdigit():
            cur.execute(
                "SELECT id, name, email, reg_code, is_active FROM students WHERE id=%s",
                (int(query),),
            )
        else:
            like = f"%{query}%"
            cur.execute(
                "SELECT id, name, email, reg_code, is_active FROM students WHERE name LIKE %s OR email LIKE %s",
                (like, like),
            )
    else:
        cur.execute("SELECT id, name, email, reg_code, is_active FROM students")
    students = cur.fetchall()
    cur.close()
    db.close()
    return render_template("admin/students.html", students=students, query=query)


@app.route("/add-student", methods=["GET", "POST"])
@admin_required
def add_student():
    if request.method == "POST":
        try:
            sid = int(request.form["student_id"])
        except ValueError:
            flash("Student ID must be a number", "error")
            return redirect(url_for("add_student"))
        name = request.form["name"]
        email = request.form["email"]
        code = gen_code()

        db = connect()
        cur = db.cursor(dictionary=True)
        try:
            cur.execute(
                "INSERT INTO students (id, name, email, reg_code) VALUES (%s, %s, %s, %s)",
                (sid, name, email, code),
            )
            db.commit()
            flash(f"Student added. Registration Code: {code}", "success")
            return redirect(url_for("view_students"))
        except:
            flash("Student already exists", "error")
        finally:
            cur.close()
            db.close()

    return render_template("admin/add_student.html")


@app.route("/update-student/<int:sid>", methods=["GET", "POST"])
@admin_required
def update_student(sid):
    db = connect()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]

        cur.execute(
            "UPDATE students SET name=%s, email=%s WHERE id=%s", (name, email, sid)
        )
        db.commit()
        flash("Student updated", "success")
        cur.close()
        db.close()
        return redirect(url_for("view_students"))

    cur.execute("SELECT id, name, email FROM students WHERE id=%s", (sid,))
    student = cur.fetchone()
    cur.close()
    db.close()

    return render_template("admin/update_student.html", student=student)


@app.route("/delete-student/<int:sid>")
@admin_required
def delete_student(sid):
    db = connect()
    cur = db.cursor(dictionary=True)
    cur.execute("DELETE FROM students WHERE id=%s", (sid,))
    db.commit()
    cur.close()
    db.close()
    flash("Student deleted", "success")
    return redirect(url_for("view_students"))


# ---- BOOK ROUTES ---- #


@app.route("/books")
@admin_required
def view_books():
    query = request.args.get("q", "").strip()
    db = connect()
    cur = db.cursor(dictionary=True)
    if query:
        like = f"%{query}%"
        cur.execute(
            "SELECT id, title, author, quantity FROM books WHERE title LIKE %s OR author LIKE %s",
            (like, like),
        )
    else:
        cur.execute("SELECT id, title, author, quantity FROM books")
    books = cur.fetchall()
    cur.close()
    db.close()
    return render_template("admin/books.html", books=books, query=query)


@app.route("/add-book", methods=["GET", "POST"])
@admin_required
def add_book():
    if request.method == "POST":
        title = request.form["title"]
        author = request.form["author"]
        quantity = int(request.form["quantity"])

        db = connect()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "INSERT INTO books (title, author, quantity) VALUES (%s, %s, %s)",
            (title, author, quantity),
        )
        db.commit()
        cur.close()
        db.close()
        flash("Book added", "success")
        return redirect(url_for("view_books"))

    return render_template("admin/add_book.html")


@app.route("/update-book/<int:bid>", methods=["GET", "POST"])
@admin_required
def update_book(bid):
    db = connect()
    cur = db.cursor(dictionary=True)

    if request.method == "POST":
        quantity = int(request.form["quantity"])
        cur.execute("UPDATE books SET quantity=%s WHERE id=%s", (quantity, bid))
        db.commit()
        flash("Book updated", "success")
        cur.close()
        db.close()
        return redirect(url_for("view_books"))

    cur.execute("SELECT id, title, author, quantity FROM books WHERE id=%s", (bid,))
    book = cur.fetchone()
    cur.close()
    db.close()

    return render_template("admin/update_book.html", book=book)


@app.route("/delete-book/<int:bid>")
@admin_required
def delete_book(bid):
    db = connect()
    cur = db.cursor(dictionary=True)
    cur.execute("DELETE FROM books WHERE id=%s", (bid,))
    db.commit()
    cur.close()
    db.close()
    flash("Book deleted", "success")
    return redirect(url_for("view_books"))


# ---- ISSUE/RETURN ROUTES ---- #


@app.route("/issue-book", methods=["GET", "POST"])
@admin_required
def issue_book():
    if request.method == "POST":
        sid = request.form["student_id"]
        bid = request.form["book_id"]

        db = connect()
        cur = db.cursor()
        cur.execute("SELECT quantity FROM books WHERE id=%s", (bid,))
        book = cur.fetchone()

        if not book or book["quantity"] <= 0:
            flash("Book unavailable", "error")
        else:
            today = date.today()
            due = today + timedelta(days=7)
            cur.execute(
                "INSERT INTO issued_books (student_id, book_id, issue_date, due_date, fine) VALUES (%s, %s, %s, %s, 0)",
                (sid, bid, today, due),
            )
            cur.execute("UPDATE books SET quantity=quantity-1 WHERE id=%s", (bid,))
            db.commit()
            flash("Book issued", "success")

        cur.close()
        db.close()
        return redirect(url_for("view_issued"))

    return render_template("admin/issue_book.html")


@app.route("/return-book", methods=["GET", "POST"])
@admin_required
def return_book():
    if request.method == "POST":
        iid = request.form["issue_id"]

        db = connect()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "SELECT book_id, due_date FROM issued_books WHERE id=%s AND return_date IS NULL",
            (iid,),
        )
        r = cur.fetchone()

        if not r:
            flash("Invalid issue ID", "error")
        else:
            fine = max(0, (date.today() - r["due_date"]).days * 5)
            cur.execute(
                "UPDATE issued_books SET return_date=%s, fine=%s WHERE id=%s",
                (date.today(), fine, iid),
            )
            cur.execute(
                "UPDATE books SET quantity=quantity+1 WHERE id=%s", (r["book_id"],)
            )
            db.commit()
            flash(f"Book returned. Fine: {fine}", "success")

        cur.close()
        db.close()
        return redirect(url_for("view_issued"))

    return render_template("admin/return_book.html")


@app.route("/issued-books")
@admin_required
def view_issued():
    db = connect()
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT * FROM issued_books")
    issued = cur.fetchall()
    cur.close()
    db.close()
    return render_template("admin/issued_books.html", issued=issued)


# ---- STUDENT ROUTES ---- #


@app.route("/activate", methods=["GET", "POST"])
def activate_student():
    if request.method == "POST":
        email = request.form["email"]
        code = request.form["code"]
        pwd = bcrypt.hashpw(request.form["password"].encode(), bcrypt.gensalt())

        db = connect()
        cur = db.cursor(dictionary=True)
        cur.execute(
            "UPDATE students SET password=%s, is_active=1, reg_code=NULL WHERE email=%s AND reg_code=%s",
            (pwd, email, code),
        )
        db.commit()
        affected = cur.rowcount
        cur.close()
        db.close()

        if affected > 0:
            flash("Account activated", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or code", "error")

    return render_template("auth/activate.html")


@app.route("/student-login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form["email"]
        pwd = request.form["password"]

        db = connect()
        cur = db.cursor()
        cur.execute(
            "SELECT id, password FROM students WHERE email=%s AND is_active=1", (email,)
        )
        r = cur.fetchone()
        cur.close()
        db.close()

        if r and bcrypt.checkpw(
            pwd.encode(),
            r["password"].encode() if isinstance(r["password"], str) else r["password"],
        ):
            login_user(User(r["id"], "student"))
            return redirect(url_for("student_dashboard"))
        else:
            flash("Invalid login", "error")

    return render_template("auth/student_login.html")


@app.route("/student-dashboard")
@student_required
def student_dashboard():
    return render_template("student/student_dashboard.html")


@app.route("/my-books")
@student_required
def my_books():
    db = connect()
    cur = db.cursor(dictionary=True)
    cur.execute(
        """
        SELECT id, student_id, book_id, issue_date, due_date, return_date, fine,
               (DATEDIFF(due_date, issue_date) > 7) AS renewed
        FROM issued_books
        WHERE student_id=%s
        """,
        (current_user.db_id,),
    )
    books = cur.fetchall()
    cur.close()
    db.close()
    return render_template("student/my_books.html", books=books)


@app.route("/search-book", methods=["GET"])
@student_required
def search_book():
    query = request.args.get("q", "").strip()
    db = connect()
    cur = db.cursor(dictionary=True)
    if query:
        like = f"%{query}%"
        cur.execute(
            "SELECT id, title, author, quantity FROM books WHERE title LIKE %s OR author LIKE %s",
            (like, like),
        )
    else:
        cur.execute("SELECT id, title, author, quantity FROM books")
    books = cur.fetchall()
    cur.close()
    db.close()
    return render_template("student/search_book.html", books=books, query=query)


@app.route("/renew/<int:iid>", methods=["POST"])
@student_required
def renew_book(iid):
    db = connect()
    cur = db.cursor(dictionary=True)
    cur.execute(
        "SELECT issue_date, due_date, return_date FROM issued_books WHERE id=%s AND student_id=%s",
        (iid, current_user.db_id),
    )
    row = cur.fetchone()
    if not row:
        flash("Invalid issue record", "error")
    elif row["return_date"] is not None:
        flash("Cannot renew a returned book", "error")
    else:
        issue_date, due_date = row["issue_date"], row["due_date"]
        if (due_date - issue_date).days > 7:
            flash("Already renewed once", "error")
        else:
            new_due = due_date + timedelta(days=7)
            cur.execute(
                "UPDATE issued_books SET due_date=%s WHERE id=%s", (new_due, iid)
            )
            db.commit()
            flash("Renewed for 7 more days", "success")
    cur.close()
    db.close()
    return redirect(url_for("my_books"))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


# ---- RUN APP ---- #

if __name__ == "__main__":
    setup()
    app.run(host="0.0.0.0", port=5000)
