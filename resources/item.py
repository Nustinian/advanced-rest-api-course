from flask_restful import Resource
from flask import request, make_response, render_template
from flask_jwt_extended import (
    jwt_required,
    fresh_jwt_required,
    get_raw_jwt,
)

from libs.strings import gettext
from models.item import ItemModel
from schemas.item import ItemSchema

item_schema = ItemSchema()
item_list_schema = ItemSchema(many=True)


class CreateItem(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        resp = make_response(render_template("/create_item.html", csrf_token=(get_raw_jwt() or {}).get("csrf")))
        return resp

    @classmethod
    @fresh_jwt_required
    def post(cls):
        name = request.form["name"]
        if ItemModel.find_by_name(name):
            return {"message": gettext("item_name_already_exists").format(name)}, 400

        price = request.form["price"]
        store_id = request.form["store_id"]
        item = item_schema.load({"name": name, "price": price, "store_id": store_id})
        try:
            item.save_to_db()
        except:
            return {"message": gettext("item_error_inserting")}, 500

        return item_schema.dump(item), 201

    @classmethod
    @jwt_required
    def put(cls):
        name = request.form["name"]
        price = request.form["price"]
        item = ItemModel.find_by_name(name)
        if item:
            item.price = price
        else:
            store_id = request.form["store_id"]
            item = item_schema.load({"name": name, "price": price, "store_id": store_id})
        try:
            item.save_to_db()
        except:
            return {"message": gettext("item_error_inserting")}, 500

        return item_schema.dump(item), 201


class Item(Resource):
    @classmethod
    def get(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            return item_schema.dump(item), 200
        return {"message": gettext("item_not_found")}, 404

    @classmethod
    @jwt_required
    def post(cls, name: str):
        if ItemModel.find_by_name(name):
            return (
                {"message": gettext("item_name_already_exists").format(name)},
                400,
            )

        item_json = request.get_json()
        item_json["name"] = name

        item = item_schema.load(item_json)

        try:
            item.save_to_db()
        except:
            return {"message": gettext("item_error_inserting")}, 500

        return item_schema.dump(item), 201

    @classmethod
    @jwt_required
    def delete(cls, name: str):
        item = ItemModel.find_by_name(name)
        if item:
            item.delete_from_db()
            return {"message": gettext("item_deleted")}, 200
        return {"message": gettext("item_not_found")}, 404

    @classmethod
    def put(cls, name: str):
        item_json = request.get_json()
        item = ItemModel.find_by_name(name)

        if item:
            item.price = item_json["price"]
        else:
            item_json["name"] = name
            item = item_schema.load(item_json)

        item.save_to_db()

        return item_schema.dump(item), 200


class ItemList(Resource):
    @classmethod
    @jwt_required
    def get(cls):
        return {"items": item_list_schema.dump(ItemModel.find_all())}, 200
