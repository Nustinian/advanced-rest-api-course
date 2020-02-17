import traceback
from flask import request, jsonify, redirect, make_response, render_template
from flask_restful import Resource
from marshmallow.exceptions import ValidationError
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    jwt_optional,
    get_raw_jwt,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)
from libs.mailgun import MailgunException
from libs.strings import gettext
from schemas.user import UserSchema
from models.user import UserModel
from models.confirmation import ConfirmationModel
from blacklist import BLACKLIST

user_schema = UserSchema()


class UserRegister(Resource):
    @classmethod
    def post(cls):
        try:
            user = user_schema.load(request.get_json())
        except ValidationError:
            username = request.form["username"]
            password = request.form["password"]
            email = request.form["email"]
            user = user_schema.load(
                {"username": username, "password": password, "email": email}
            )

        if UserModel.find_by_username(user.username):
            return {"message": gettext("user_already_exists")}, 400

        if UserModel.find_by_email(user.email):
            return {"message": gettext("user_email_already_exists")}, 400
        try:
            user.save_to_db()
            confirmation = ConfirmationModel(user.id)
            confirmation.save_to_db()
            user.send_confirmation_email()
        except MailgunException as e:
            user.delete_from_db()
            return {"message": str(e)}, 500
        except:
            user.delete_from_db()
            traceback.print_exc()
            return {"message": gettext("user_failed_to_create")}, 500
        return {"message": gettext("user_created_successfully")}, 201


class User(Resource):
    """
    This resource can be useful when testing our Flask app. We may not want to expose it to public users, but for the
    sake of demonstration in this course, it can be useful when we are manipulating data regarding the users.
    """

    @classmethod
    def get(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": gettext("user_not_found")}, 404
        return user_schema.dump(user), 200

    @classmethod
    def delete(cls, user_id: int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {"message": gettext("user_not_found")}, 404
        user.delete_from_db()
        return {"message": gettext("user_deleted")}, 200


class UserLogin(Resource):
    @classmethod
    def post(cls):
        try:
            user_data = user_schema.load(request.get_json(), partial=("email",))
        except ValidationError:
            username = request.form["username"]
            password = request.form["password"]
            user_data = user_schema.load(
                {"username": username, "password": password}, partial=("email",)
            )

        user = UserModel.find_by_username(user_data.username)

        # this is what the `authenticate()` function did in security.py
        if user and safe_str_cmp(user.password, user_data.password):
            confirmation = user.most_recent_confirmation
            if not confirmation.confirmed:
                return {"message": gettext("user_not_yet_activated")}, 400
            access_token = create_access_token(identity=user.id, fresh=True)
            refresh_token = create_refresh_token(user.id)
            resp = make_response(redirect("/login/success", code=302))
            set_access_cookies(resp, access_token)
            set_refresh_cookies(resp, refresh_token)
            return resp
        return redirect("/login/fail", code=401)


class UserLogout(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        resp = make_response(render_template("/logout_page.html", csrf_token=(get_raw_jwt() or {}).get("csrf")))
        return resp

    @classmethod
    @jwt_required
    def post(cls):
        jti = get_raw_jwt()["jti"]  # jti is "JWT ID", a unique identifier for a JWT.
        user_id = get_jwt_identity()
        BLACKLIST.add(jti)
        resp = make_response(redirect(f"/logout/{user_id}", code=200))
        unset_jwt_cookies(resp)
        return resp


class TokenRefresh(Resource):
    @classmethod
    @jwt_refresh_token_required
    def get(cls):
        resp = make_response(render_template("/refresh_page.html", csrf_token=(get_raw_jwt() or {}).get("csrf")))
        return resp

    @classmethod
    @jwt_refresh_token_required
    def post(cls):
        current_user = get_jwt_identity()
        new_token = create_access_token(identity=current_user, fresh=False)
        resp = make_response(render_template("post_refresh.html", code=302))
        set_access_cookies(resp, new_token)
        return resp
