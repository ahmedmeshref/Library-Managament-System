#!/bin/env python

import os

from Library_Management_System import app as application
from Library_Management_System import db
from Library_Management_System.views import main

application.register_blueprint(main)
db.create_all()
if __name__ == "__main__":
    application.run("0.0.0.0", threaded=True)