#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import datetime
import logging
import hashlib
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from argparse import ArgumentParser
from scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500

ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}

UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

class Field:
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, instance, owner):
        return instance.__dict__.get(self.name, None)

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value

    def validate(self, value):
        if self.required and value is None:
            raise ValueError(f"{self.name} is required")
        if not self.nullable and value is None:
            raise ValueError(f"{self.name} cannot be null")
        return value


class CharField(Field):
    def validate(self, value):
        super().validate(value)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{self.name} must be a string")
        return value


class ArgumentsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValueError(f"{self.name} должно быть словарём")
        return value


class EmailField(CharField):
    def validate(self, value):
        value = super().validate(value)
        if value and "@" not in value:
            raise ValueError(f"{self.name} должно содержать '@'")
        return value


class PhoneField(Field):
    def validate(self, value):
        super().validate(value)
        if value is None:
            return value
        if isinstance(value, str):
            if not value.isdigit():
                raise ValueError(f"{self.name} должно содержать только цифры")
            value = int(value)
        if not isinstance(value, int):
            raise ValueError(f"{self.name} должно быть числом")
        s = str(value)
        if len(s) != 11 or not s.startswith("7"):
            raise ValueError(f"{self.name} должно начинаться с '7' и быть длиной 11")
        return value
class DateField(Field):
    def validate(self, value):
        super().validate(value)
        try:
            datetime.datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            raise ValueError(f"{self.name} должно быть в формате DD.MM.YYYY")
        return value


class BirthDayField(DateField):
    def validate(self, value):
        super().validate(value)
        dt = datetime.datetime.strptime(value, "%d.%m.%Y")
        today = datetime.datetime.today()
        if (today - dt).days > 70 * 365:
            raise ValueError(f"{self.name} — возраст должен быть не более 70 лет")
        return value


class GenderField(Field):
    def validate(self, value):
        super().validate(value)
        if value not in (0, 1, 2):
            raise ValueError(f"{self.name} должно быть 0, 1 или 2")
        return value


class ClientIDsField(Field):
    def validate(self, value):
        super().validate(value)
        if not isinstance(value, list):
            raise ValueError(f"{self.name} должно быть списком")
        if not all(isinstance(x, int) for x in value):
            raise ValueError(f"{self.name} должно содержать только числа")
        return value
class RequestMeta(type):
    def __new__(cls, name, bases, attrs):
        fields = {k: v for k, v in attrs.items() if isinstance(v, Field)}
        for k in fields:
            attrs[k] = fields[k]
        attrs["_fields"] = fields
        return super().__new__(cls, name, bases, attrs)


class BaseRequest(metaclass=RequestMeta):
    def __init__(self, data):
        self.errors = {}
        self.cleaned_data = {}
        self.raw_data = data or {}

        for name, field in self._fields.items():
            value = self.raw_data.get(name)
            try:
                if value is None and field.required:
                    raise ValueError(f"{name} is required")
                if value == "" and not field.nullable:
                    raise ValueError(f"{name} cannot be empty")
                validated = field.validate(value)
                setattr(self, name, validated)
                self.cleaned_data[name] = validated
            except Exception as e:
                self.errors[name] = str(e)

    def is_valid(self):
        return not self.errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate_logic(self):
        pairs = [
            ("phone", "email"),
            ("first_name", "last_name"),
            ("birthday", "gender"),
        ]
        for a, b in pairs:
            if self.cleaned_data.get(a) and self.cleaned_data.get(b):
                return
        raise ValueError("Должна быть заполнена хотя бы одна из пар: phone+email, first_name+last_name, birthday+gender")


class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode("utf-8")).hexdigest()
    else:
        account = request.cleaned_data.get("account") or ""
        login = request.cleaned_data.get("login") or ""
        digest = hashlib.sha512((account + login + SALT).encode("utf-8")).hexdigest()
    return digest == request.token


def method_handler(request, ctx, store):
    method_request = MethodRequest(request["body"])
    if not method_request.is_valid():
        return method_request.errors, INVALID_REQUEST

    if not check_auth(method_request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    method = method_request.method
    arguments = method_request.arguments
    ctx["method"] = method

    if method == "online_score":
        if method_request.is_admin:
            return {"score": 42}, OK

        score_request = OnlineScoreRequest(arguments)
        if not score_request.is_valid():
            return score_request.errors, INVALID_REQUEST
        try:
            score_request.validate_logic()
        except Exception as e:
            return str(e), INVALID_REQUEST

        ctx["has"] = [k for k, v in score_request.cleaned_data.items() if v is not None]
        score = get_score(
            store,
            phone=score_request.phone,
            email=score_request.email,
            birthday=score_request.birthday,
            gender=score_request.gender,
            first_name=score_request.first_name,
            last_name=score_request.last_name,
        )
        return {"score": score}, OK

    elif method == "clients_interests":
        interests_request = ClientsInterestsRequest(arguments)
        if not interests_request.is_valid():
            return interests_request.errors, INVALID_REQUEST
        ctx["nclients"] = len(interests_request.cleaned_data["client_ids"])
        response = {
            cid: get_interests(store, cid)
            for cid in interests_request.cleaned_data["client_ids"]
        }
        return response, OK

    return f"Метод '{method}' не поддерживается", NOT_FOUND


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get("HTTP_X_REQUEST_ID", uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers["Content-Length"]))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode("utf-8"))
        return


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", action="store", type=int, default=8080)
    parser.add_argument("-l", "--log", action="store", default=None)
    args = parser.parse_args()
    logging.basicConfig(filename=args.log, level=logging.INFO,
                        format="[%(asctime)s] %(levelname).1s %(message)s", datefmt="%Y.%m.%d %H:%M:%S")
    server = HTTPServer(("localhost", args.port), MainHTTPHandler)
    logging.info("Starting server at %s" % args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
