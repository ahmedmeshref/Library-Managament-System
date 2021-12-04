"""
Routes and views for the flask application.
"""
import re
from datetime import datetime, timedelta
from functools import wraps

from flask import flash, redirect, render_template, request, url_for
import flask
from flask.blueprints import Blueprint
from flask.views import MethodView
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from . import db, login_manager
from .models import Book, Lend, User

main = Blueprint("main", __name__)

def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
    """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'symbol_error' : symbol_error,
    }
    
def requires_librarian(f):
    """Checks if user has librarian access"""

    @wraps(f)
    def wrapped(*args, **kwargs):
        if current_user.librarian:
            return f(*args, **kwargs)
        return unauthorized()

    return wrapped


def requires_admin(f):
    """Checks if user has admin access"""

    @wraps(f)
    def wrapped(*args, **kwargs):
        if current_user.admin:
            return f(*args, **kwargs)
        return unauthorized()

    return wrapped

def get_book_object(lended_books):
    lended_books_dict = {}
    ind = 0
    for lended_book in lended_books:
        book_info = Book.query.filter_by(id=lended_book.book_id).first()
        user_info = User.query.filter_by(id=lended_book.user_id).first()
        lended_books_dict[ind] = {
            "lend_info": lended_book,
            "book_info": book_info,
            "user_info": user_info
        }
        ind += 1
    return lended_books_dict

@login_manager.user_loader
def load_user(user_id: int):
    return User.query.get(user_id)


@main.route("/", methods=["GET"])
def index():
    """Home Page"""
    books = Book.query.all()
    if books:
        return render_template("index.html", year=datetime.now().year, books=books)
    flash("No books are in library!", "info")
    return render_template("index.html", year=datetime.now().year)


class LoginView(MethodView):
    def get(self):
        return render_template("login.html", year=datetime.now().year)

    def post(self):
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            return redirect(url_for("main.dashboard"))
        flash("Invalid Credentials!", "danger")
        return redirect(url_for("main.login"))


class RegisterView(MethodView):
    def get(self):
        return render_template("register.html", year=datetime.now().year)

    def post(self):
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        password_checker = password_check(password)
        if not password_checker["password_ok"]:
            if password_checker["length_error"]:
                flash("Your password should be at least 8 chars long!", "danger")
                return redirect(url_for("main.register"))
            if password_checker["digit_error"]:
                flash("Your password should include at least 1 digits!", "danger")
                return redirect(url_for("main.register"))
            elif password_checker["uppercase_error"]:
                flash("Your password should include at least 1 UpperCase letter", "danger")
                return redirect(url_for("main.register"))
            elif password_checker["symbol_error"]:
                flash("Your password doesn't include at least 1 Symbol", "danger")
                return redirect(url_for("main.register"))
        hash_password = generate_password_hash(password, method="sha256")
        if User.query.filter_by(email=email).first():
            flash("This email already exists!", "danger")
            return redirect(url_for("main.register"))
        user = User(name=name, email=email, password=hash_password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        if request.args.get("next"):
            return redirect(request.args.get("next"))
        return redirect(url_for("main.dashboard"))


class LibrarianView(MethodView):
    def get(self):
        return render_template("librarian.html")

    def post(self):
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email, librarian=True).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            return redirect(url_for("main.librarian_dashboard"))
        flash("Invalid librarian Credentials!", "danger")
        return redirect(url_for("main.librarian")) 


class AdminView(MethodView):
    def get(self):
        return render_template("admin.html")

    def post(self):
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter(User.email==email, User.admin==True).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if request.args.get("next"):
                return redirect(request.args.get("next"))
            return redirect(url_for("main.admin_dashboard"))
        flash("Invalid admin Credentials!", "danger")
        return redirect(url_for("main.admin")) 

@main.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    borrowed_books = Lend.query.filter_by(user_id=current_user.id).all()
    borrowed_books_obj = {}
    if not borrowed_books:
        flash("You didn't borrow any books yet!", "info")
    else:
        borrowed_books_obj = get_book_object(borrowed_books)
    return render_template("dashboard.html", books_obj=borrowed_books_obj)


@main.route("/librarian/dashboard", methods=["GET"])
@login_required
@requires_librarian
def librarian_dashboard():
    books = Book.query.all()
    if not books:
        flash("No books found in library!", "info")
    return render_template(
        "librarian_dashboard.html", books=books
    )


@main.route("/admin/dashboard", methods=["GET"])
@login_required
@requires_admin
def admin_dashboard():
    users = User.query.all()
    if not users:
        flash("No users are found on the system!", "info")
   
    return render_template(
        "admin_dashboard.html", users=users
    )

class AddBookView(MethodView):
    def get(self):
        return render_template("add_book.html", year=datetime.now().year)

    def post(self):
        name = request.form.get("name")
        author = request.form.get("author")
        description = request.form.get("description")
        copies = int(request.form.get("number"))
        book = Book.query.filter_by(name=name).first()
        if book:
            flash("Book with the same title already exists!", "danger")
            return redirect(url_for("main.add_book"))
        book = Book(
            name=name,
            author=author,
            description=description,
            total_quantity=copies,
            available_quantity=copies,
        )
        db.session.add(book)
        db.session.commit()
        db.session.close()
        flash("Book added successfully!", "success")
        return redirect(url_for("main.librarian_dashboard"))


class AddUserView(MethodView):
    def get(self):
        return render_template("add_user.html")

    def post(self):
        name = request.form.get("username")
        email = request.form.get("email")
        privilege = request.form.get("privilege")
        password = request.form.get("password")
        password_checker = password_check(password)
        if not password_checker["password_ok"]:
            if password_checker["length_error"]:
                flash("Password should be at least 8 chars long!", "danger")
                return redirect(url_for("main.add_user"))
            if password_checker["digit_error"]:
                flash("Password should include at least 1 digits!", "danger")
                return redirect(url_for("main.add_user"))
            elif password_checker["uppercase_error"]:
                flash("Password should include at least 1 UpperCase letter", "danger")
                return redirect(url_for("main.add_user"))
            elif password_checker["symbol_error"]:
                flash("Password doesn't include at least 1 Symbol", "danger")
                return redirect(url_for("main.add_user"))
        hash_password = generate_password_hash(password, method="sha256")
        if User.query.filter_by(email=email).first():
            flash("User with the same email already exists!", "danger")
            return redirect(url_for("main.add_user"))
        librarian, admin = False, False 
        if privilege == "0":
            admin = True
        elif privilege == "1":
            librarian = True
        user = User(name=name, email=email, password=hash_password, admin=admin, librarian=librarian)
        db.session.add(user)
        db.session.commit()
        flash("User added successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))


class RemoveUserView(MethodView):
    def get(self):
        users=User.query.filter(User.email != current_user.email).all()
        if not users:
            flash("No users are available to be removed!", "info")
        return render_template(
            "remove_user.html", users=users
        )

    def post(self):
        user_id = int(request.form.get("user"))
        user = User.query.filter(User.id==user_id).first()
        if not user:
            flash("User doesn't exist!", "danger")
            return redirect(url_for("main.remove_user"))
        db.session.delete(user)
        db.session.commit()
        flash("User removed successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))


class ChangePrivilegesView(MethodView):
    def get(self):
        users=User.query.filter(User.email != current_user.email).all()
        if not users:
            flash("No users are available!", "info")
        return render_template(
            "change_privileges.html", users=users
        )

    def post(self):
        user_id = int(request.form.get("user"))
        privilege = request.form.get("privilege")
        user = User.query.filter(User.id==user_id).first()
        if not user:
            flash("User doesn't exists!", "danger")
            return redirect(url_for("main.change_privileges"))

        librarian, admin = False, False 
        if privilege == "0":
            admin = True
        elif privilege == "1":
            librarian = True

        user.admin = admin
        user.librarian = librarian
        db.session.commit()
        flash("Privilege granted successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))        


@main.route("/book/<int:book_id>/update", methods=['GET', 'POST'])
@login_required
@requires_librarian
def update_book(book_id):
    book = Book.query.filter(Book.id == book_id).first()
    if not book:
        flash("No book with that id exists!", "danger")
        return redirect(url_for("main.librarian_dashboard"))
    if request.method == 'POST':
        book_title = request.form.get("name")
        copies = int(request.form.get("number"))
        book_description = request.form.get("description")
        book.title = book_title
        book.description = book_description
        book.total_quantity = copies
        book.available_quantity += copies
        db.session.commit()
        flash(f"Book updated successfully!", "success")
        db.session.close()
        return redirect(url_for("main.librarian_dashboard"))
    return render_template(
            "update_book.html", book=book
        )


class LendBookView(MethodView):
    def get(self):
        books = Book.query.filter(Book.available_quantity > 0).all()
        if not books:
            flash("No books are currently available!", "info")
        return render_template(
            "lend.html", books=Book.query.all(), users=User.query.all() ,year=datetime.now().year
        )

    def post(self):
        book_id = int(request.form.get("book"))
        book = db.session.query(Book).filter(Book.id == book_id).first()
        user_id = int(request.form.get("user"))
        user = db.session.query(User).filter(User.id == user_id).first()
        lend_date, return_date = request.form.get("daterange").split(" - ")
        date_added = datetime.strptime(lend_date, '%m/%d/20%y')
        return_date = datetime.strptime(return_date, '%m/%d/20%y')
        borrowed_before = db.session.query(Lend).filter(Lend.user_id==user_id).filter(Lend.book_id==book_id).filter(Lend.lent_state==False).first()
        if not book or not user:
            flash("Book or user don't exist!", 'danger')
            return redirect(url_for("main.librarian_dashboard"))

        if book.available_quantity <= 0:
            flash("This book is not avaliable at the moment!", 'danger')
            return redirect(url_for("main.librarian_dashboard"))

        if borrowed_before:
            flash("Same book is borrowed by the same user and not returned yet!", "danger")
            return redirect(url_for("main.librarian_dashboard"))

        if return_date < date_added:
            flash("Return date should happen after the lend date!", "danger")
            return redirect(url_for("main.librarian_dashboard"))

        book.available_quantity -= 1
        lent = Lend(
            user_id=user_id,
            book_id=book_id,
            date_issued=datetime.now(),
            date_added=date_added,
            date_return=return_date
        )
        db.session.add(lent)
        db.session.commit()
        flash(f"Lended Book: '{book.name}' to user: '{user.name}' successfully!", "success")
        db.session.close()
        return redirect(url_for("main.librarian_dashboard"))


class ReturnBookView(MethodView):
    def get(self):
        lended_books = Lend.query.filter_by(lent_state=False).all()
        lended_books_dict = {}
        if not lended_books:
            flash("No lended books found at the moment!", "warning")
        else:
            lended_books_dict = get_book_object(lended_books)
        return render_template(
            "return.html", books_obj=lended_books_dict 
        )

    def post(self):
        lend_id = request.form.get("book")
        lend = Lend.query.filter_by(id=lend_id).first()
        if not lend:
            flash("No borrow record matches the given book and user!", "danger")
            return redirect(url_for("main.librarian_dashboard"))
        
        book = Book.query.filter_by(id=lend.book_id).first()
        book.available_quantity += 1
        # mark book as returned book 
        lend.date_return = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        lend.lent_state = True 
        db.session.commit()
        flash("Book returned successfully!", "success")
        return redirect(url_for("main.librarian_dashboard"))


class RemoveBookView(MethodView):
    def get(self):
        books = Book.query.all()
        if not books:
            flash("No books are available to be removed!", "info")
        return render_template(
            "remove_book.html", year=datetime.now().year, books=Book.query.all()
        )

    def post(self):
        book_id = int(request.form.get("book"))
        book = Book.query.filter_by(id=book_id).first()
        db.session.delete(book)
        db.session.commit()
        flash("Book removed successfully!", "success")
        return redirect(url_for("main.librarian_dashboard"))


main.add_url_rule("/register", view_func=RegisterView.as_view("register"))
main.add_url_rule("/login", view_func=LoginView.as_view("login"))
main.add_url_rule("/librarian", view_func=LibrarianView.as_view("librarian"))
main.add_url_rule(
    "/add/book",
    view_func=login_required(requires_librarian(AddBookView.as_view("add_book"))),
)
main.add_url_rule(
    "/return/book", view_func=login_required(requires_librarian(ReturnBookView.as_view("return_book")))
)
main.add_url_rule(
    "/remove/book", view_func=login_required(requires_librarian(RemoveBookView.as_view("remove_book")))
)
main.add_url_rule(
    "/lend/book", view_func=login_required(requires_librarian(LendBookView.as_view("issue_book")))
)
main.add_url_rule("/admin", view_func=AdminView.as_view("admin"))
main.add_url_rule(
    "/add/user", view_func=login_required(requires_admin(AddUserView.as_view("add_user")))
)
main.add_url_rule(
    "/remove/user", view_func=login_required(requires_admin(RemoveUserView.as_view("remove_user")))
)
main.add_url_rule(
    "/change/privileges", view_func=login_required(requires_admin(ChangePrivilegesView.as_view("change_privileges")))
)


@main.route('/search_results', methods=['POST'])
@login_required
def search():
    search_text = request.form['search_value']
    books = Book.query.filter(Book.name.ilike(f"%{search_text}%")).all()
    return render_template("search_results.html", books=books, keyword=search_text)

@main.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@login_manager.unauthorized_handler
def unauthorized():
    flash("You are not authorized to access the content!", "danger")
    logout_user()
    return redirect(url_for("main.login"))
