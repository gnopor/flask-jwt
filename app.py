from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, get_raw_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

# import our own module
from fakeDB import fakeDB

###############################
# instanciate app

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'gnopor'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=7)
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

################################
# helpers


def findUser(db, email):
    for user in db:
        if user['email'] == email:
            return user


blacklist = set()

# This method will be called whenever the specified tokens(access and / or refresh) are used to access a protected endpoint


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return jti in blacklist


##############################
# register our route
# 1. register user


@app.route('/register', methods=['POST'])
def register():
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    try:
        # 1. Check if user exist
        user = findUser(fakeDB, email)

        if user:
            raise Exception("user already exist")

        # 2. If no user, hashpassword
        hashedPassword = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=10)

        # 3. Insert user in 'database'
        fakeDB.append(
            {
                'id': len(fakeDB),
                'email': email,
                'password': hashedPassword
            }
        )

        # print(fakeDB)

        return jsonify({'messsage': 'User created'}), 200
    except Exception as e:
        return jsonify({"Error": repr(e)}), 400

# 2. Login


@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email', None)
    password = request.json.get('password', None)

    try:
        # 1. Find user in 'database'. If not exist send error
        user = findUser(fakeDB, email)
        if user is None:
            raise Exception("User doesn't")

        # 2. Compare crypted password and see if check, Send error if not
        valid = check_password_hash(user['password'], password)
        if not valid:
            raise Exception('Password not correct')
        # 3. Create refresh and access token
        access_token = create_access_token(
            identity=user['id'], expires_delta=None)
        refresh_token = create_refresh_token(
            identity=user['id'], expires_delta=None)

        # 4. send tokens

        ret = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        return jsonify(ret), 200
    except Exception as e:
        return jsonify({'Error': repr(e)})


# 3. Logout a user
# Endpoint for revoking the current users access token
@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
  # In a protected endpoint, this will return the python dictionary which has all of the claims of the JWT that is accessing the endpoint
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200


# Endpoint for revoking the current users refresh token
@app.route('/logout2', methods=['POST'])
@jwt_refresh_token_required
def logout2():
    jti = get_raw_jwt()['jti']
    blacklist.add(jti)
    return jsonify({"message": "Successfully logged out"}), 200

# 4. Protected route


@app.route('/protected', methods=['POST'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify(logged_in_as=username), 200

# 5. Get a new access token with a refresh token


@app.route('/refresh_token', methods=['POST'])
@jwt_refresh_token_required
def refresh():
  # this endpoint will be call everytime access_token has expired and that is why we don't have to worry about it be used later
  # we just have to send a new one
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user, expires_delta=None)
    }
    return jsonify(ret), 200


###############################
# launch app
if __name__ == '__main__':
    app.run(debug=True, port=4000)
