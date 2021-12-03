"""
Routes and views for the flask application.
"""

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
    flash("No books are in library!")
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
        flash("Invalid Credentials!")
        return redirect(url_for("main.login"))


class RegisterView(MethodView):
    def get(self):
        return render_template("register.html", year=datetime.now().year)

    def post(self):
        name = request.form.get("name")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"), method="sha256")
        if User.query.filter_by(email=email).first():
            flash("User already exists!")
            return redirect(url_for("main.register"))
        user = User(name=name, email=email, password=password)
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
        flash("Invalid librarian Credentials!")
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
        flash("Invalid admin Credentials!")
        return redirect(url_for("main.admin")) 

@main.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    borrowed_books = Lend.query.filter_by(user_id=current_user.id).all()
    borrowed_books_obj = {}
    if not borrowed_books:
        flash("You didn't borrow any books yet!")
    else:
        borrowed_books_obj = get_book_object(borrowed_books)
    return render_template("dashboard.html", books_obj=borrowed_books_obj)


@main.route("/librarian/dashboard", methods=["GET"])
@login_required
@requires_librarian
def librarian_dashboard():
    books = Book.query.all()
    if not books:
        flash("No books found in library!")
    return render_template(
        "librarian_dashboard.html", books=books
    )


@main.route("/admin/dashboard", methods=["GET"])
@login_required
@requires_admin
def admin_dashboard():
    users = User.query.all()
    if not users:
        flash("No users are found on the system!")
   
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
        copies = int(request.form.get("copies"))
        book = Book.query.filter_by(name=name).first()
        if book:
            flash("Book with the same title already exists!")
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
        flash("Book added successfully!")
        return redirect(url_for("main.librarian_dashboard"))


class AddUserView(MethodView):
    def get(self):
        return render_template("add_user.html")

    def post(self):
        name = request.form.get("username")
        email = request.form.get("email")
        privilege = request.form.get("privilege")
        password = generate_password_hash(request.form.get("password"), method="sha256")
        print(User.query.filter(User.email==email).first())
        if User.query.filter_by(email=email).first():
            flash("Error - User with the same email already exists!")
            return redirect(url_for("main.add_user"))
        librarian, admin = False, False 
        if privilege == "0":
            admin = True
        elif privilege == "1":
            librarian = True
        user = User(name=name, email=email, password=password, admin=admin, librarian=librarian)
        db.session.add(user)
        db.session.commit()
        flash("User added successfully!")
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
            flash("Error - User can't be found!", "error")
            return redirect(url_for("main.remove_user"))
        db.session.delete(user)
        db.session.commit()
        flash("User removed successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))


class ChangePrivilegesView(MethodView):
    def get(self):
        users=User.query.filter(User.admin==False).all()
        if not users:
            flash("No users are available!", "info")
        return render_template(
            "change_privileges.html", users=users
        )

    def post(self):
        flash("Privilege removed successfully!", "success")
        return redirect(url_for("main.admin_dashboard"))


class LendBookView(MethodView):
    def get(self):
        books = Book.query.filter(Book.available_quantity > 0).all()
        if not books:
            flash("No books are currently available!")
        return render_template(
            "lend.html", books=Book.query.all(), users=User.query.all() ,year=datetime.now().year
        )

    def post(self):
        # TODO: remove this line
        if current_user.email == 'ahmedmeshref@gmail.com':
            flash("Sorry, you are not authorized to perform this action! Please contact the admin for more info.", 'error')
            return redirect(url_for("main.librarian_dashboard"))
        book_id = int(request.form.get("book"))
        book = db.session.query(Book).filter(Book.id == book_id).first()
        user_id = int(request.form.get("user"))
        user = db.session.query(User).filter(User.id == user_id).first()
        lend_date, return_date = request.form.get("daterange").split(" - ")
        borrowed_before = db.session.query(Lend).filter(Lend.user_id==user_id).filter(Lend.book_id==book_id).filter(Lend.lent_state==False).first()
        if book.available_quantity <= 0:
            flash("Error - This book is not avaliable at the moment!", 'error')
            return redirect(url_for("main.librarian_dashboard"))

        if not book or not user:
            flash("Error - Book or user don't exist!", 'error')
            return redirect(url_for("main.librarian_dashboard"))

        if borrowed_before:
            flash("Error - Same book is borrowed by the same user and not returned yet!", "error")
            return redirect(url_for("main.librarian_dashboard"))

        book.available_quantity -= 1
        lent = Lend(
            user_id=user_id,
            book_id=book_id,
            date_issued=datetime.now(),
            date_added=datetime.strptime(lend_date, '%m/%d/20%y'),
            date_return=datetime.strptime(return_date, '%m/%d/20%y')
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
            flash("No lended books found at the moment!", "info")
        else:
            lended_books_dict = get_book_object(lended_books)
        return render_template(
            "return.html", books_obj=lended_books_dict 
        )

    def post(self):
        lend_id = request.form.get("book")
        lend = Lend.query.filter_by(id=lend_id).first()
        if not lend:
            flash("No borrow record matches the given book and user!", "error")
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
    flash("You are not authorized to access the content!", "error")
    logout_user()
    return redirect(url_for("main.login"))
