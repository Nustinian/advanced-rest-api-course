import os

from flask import Flask, jsonify, render_template
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_uploads import configure_uploads, patch_request_class
from flask_migrate import Migrate
from marshmallow import ValidationError
from dotenv import load_dotenv

from db import db
from ma import ma
from blacklist import BLACKLIST
from resources.user import UserRegister, UserLogin, User, TokenRefresh, UserLogout
from resources.item import Item, ItemList, CreateItem
from resources.store import Store, StoreList, CreateStore
from resources.confirmation import Confirmation, ConfirmationByUser
from resources.image import ImageUpload, Image, AvatarUpload, Avatar
from schemas.image import FileStorageField
from libs.image_helper import IMAGE_SET
from libs.strings import gettext

app = Flask(__name__)
load_dotenv(".env", verbose=True)
app.config.from_object("default_config")
app.config.from_envvar("APPLICATION_SETTINGS")
patch_request_class(app, 10 * 1024 * 1024)
configure_uploads(app, IMAGE_SET)
api = Api(app)
migrate = Migrate(app, db)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/confirmation.html/")
def confirmationpage():
    return render_template("confirmation.html")


@app.route("/image.html/")
def imagepage():
    return render_template("image.html")


@app.route("/item.html/")
def itempage():
    return render_template("item.html")


@app.route("/store.html/")
def storepage():
    return render_template("store.html")


@app.route("/user.html/")
def userpage():
    return render_template("user.html")


@app.route("/login/<string:response>/")
def postloginpage(response):
    if response == "success":
        return render_template("post_login.html", text=gettext("user_logged_in"))
    return render_template("post_login.html", text=gettext("user_invalid_credentials"))


@app.route("/logout/<int:user_id>/")
def postlogoutpage(user_id):
    return render_template(
        "post_logout.html", text=gettext("user_logged_out").format(user_id)
    )


@app.before_first_request
def create_tables():
    db.create_all()


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "max-age=0"
    return response


@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err):
    return jsonify(err.messages), 400


jwt = JWTManager(app)

# This method will check if a token is blacklisted, and will be called automatically when blacklist is enabled
@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    return (
        decrypted_token["jti"] in BLACKLIST
    )  # Here we blacklist particular JWTs that have been created in the past.


#@jwt.unauthorized_loader
#def missing_token_callback(error):
#    return (
#        jsonify(
#            {
#                "description": "Request does not contain an access token. You can get an access token by logging in, or refreshing if you have a refresh token.",
#                "error": "authorization_required",
#            }
#        ),
#        401,
#    )


api.add_resource(StoreList, "/stores")
api.add_resource(Store, "/store/<string:name>")
api.add_resource(ItemList, "/items")
api.add_resource(Item, "/item/<string:name>")
api.add_resource(UserRegister, "/register")
api.add_resource(User, "/user/<int:user_id>")
api.add_resource(UserLogin, "/login")
api.add_resource(TokenRefresh, "/refresh")
api.add_resource(UserLogout, "/logout")
api.add_resource(Confirmation, "/user_confirm/<string:confirmation_id>")
api.add_resource(ConfirmationByUser, "/confirmation/user/<int:user_id>")
api.add_resource(ImageUpload, "/upload/image")
api.add_resource(Image, "/image/<string:filename>")
api.add_resource(AvatarUpload, "/upload/avatar")
api.add_resource(Avatar, "/avatar/<int:user_id>")
api.add_resource(CreateStore, "/store/create")
api.add_resource(CreateItem, "/item/create")

if __name__ == "__main__":
    db.init_app(app)
    ma.init_app(app)
    app.run(port=5000)
