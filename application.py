from flask import (Flask,
                   render_template,
                   request, redirect,
                   jsonify,
                   url_for,
                   flash)
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import (Base,
                            User,
                            Category,
                            CategoryItem)
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

# Create Database engine

engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create login classes
@app.route('/login')
def showLogin():

    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state, client_id=CLIENT_ID)


# Start Google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    api_url = 'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token='
    url = '%s%s' % (api_url, access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data.get('name', '')
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:\
150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    if 'username' in login_session:
        gdisconnect()
        del login_session['gplus_id']
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        flash("You have successfully been logged out.")
        return redirect(url_for('categoryList'))
    else:
        flash("You were not logged in")
        return redirect(url_for('categoryList'))


# User Helper Functions


def createUser(login_session):
    newUser = User(user_name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.user_id


def getUserInfo(user_id):
    user = session.query(User).filter_by(user_id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.user_id
    except:
        return None


# End Google login

# JSON APIs to view Category Information
@app.route('/categories/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(Categories=[r.serialize for r in categories])


@app.route('/categories/<int:url_category_id>/JSON')
def categoryListJSON(url_category_id):
    category = session.query(Category).filter_by(
        category_id=url_category_id).one()
    items = session.query(CategoryItem).filter_by(
        itm_cat_id=url_category_id).all()
    return jsonify(ListItems=[i.serialize for i in items])


@app.route('/categories/<int:url_category_id>/list/<int:url_item_id>/JSON')
def categoryListItemJSON(url_category_id, url_item_id):
    category = session.query(Category).filter_by(
        category_id=url_category_id).one()
    item = session.query(CategoryItem).filter_by(item_id=url_item_id).one()
    return jsonify(ListItems=item.serialize)

# Start categories and items routing


@app.route('/')
@app.route('/categories')
def categoryList():
    categories = session.query(Category).all()
    if 'username' not in login_session:
        return render_template('categoriespublic.html', categories=categories)
    else:
        return render_template('categories.html', categories=categories)


@app.route('/categories/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if request.method == 'POST':
        newCat = Category(category_name=request.form['name'],
                          cat_user_id=login_session['user_id'])
        session.add(newCat)
        session.commit()
        return redirect(url_for('categoryList'))
    else:
        return render_template('newcategory.html')


@app.route('/categories/<int:url_category_id>/edit',
           methods=['GET', 'POST'])
def editCategory(url_category_id):
    editedCat = session.query(Category).filter_by(
        category_id=url_category_id).one()
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if editedCat.cat_user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this \
        category. Please create your own category in order to edit.');}\
        </script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedCat.category_name = request.form['name']
        session.add(editedCat)
        session.commit()
        return redirect(url_for('categoryList'))
    else:
        return render_template(
                               'editcategory.html',
                               url_category_id=url_category_id,
                               category=editedCat)


@app.route('/categories/<int:url_category_id>/delete',
           methods=['GET', 'POST'])
def deleteCategory(url_category_id):
    CategoryToDelete = session.query(
        Category).filter_by(category_id=url_category_id).one()
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    if CategoryToDelete.cat_user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this \
        category. Please create your own category in order to delete.');}\
        </script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(CategoryToDelete)
        session.commit()
        return redirect(url_for('categoryList'))
    else:
        return render_template('deletecategory.html', item=CategoryToDelete)


@app.route('/categories/<int:url_category_id>/categoryitemlist')
def categoryItemList(url_category_id):
    category = session.query(
        Category).filter_by(category_id=url_category_id).one()
    creator = getUserInfo(category.cat_user_id)
    items = session.query(CategoryItem).filter_by(itm_cat_id=url_category_id)
    if 'username' not in login_session or\
            creator.user_id != login_session['user_id']:
        return render_template(
            'categoryitemlistpublic.html', items=items,
            category=category, creator=creator)
    else:
        return render_template(
            'categoryitemlist.html', category=category,
            items=items, creator=creator)


@app.route('/categories/<int:url_category_id>/new', methods=['GET', 'POST'])
def newCategoryItem(url_category_id):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    category = session.query(
        Category).filter_by(category_id=url_category_id).one()
    if login_session['user_id'] != category.cat_user_id:
        return "<script>function myFunction() {alert('You are not authorized to add \
        category items to this category. Please create your own category in \
        order to add items.');}</script><body onload='myFunction()'>"

    if request.method == 'POST':
        newItem = CategoryItem(item_name=request.form['name'],
                               price=request.form['price'],
                               description=request.form['description'],
                               producer=request.form['producer'],
                               itm_cat_id=url_category_id,
                               itm_user_id=category.cat_user_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('categoryItemList',
                                url_category_id=url_category_id))
    else:
        return render_template('newcategoryitem.html', category=category,
                               url_category_id=url_category_id)


@app.route('/categories/<int:url_category_id>/<int:url_item_id>/edit',
           methods=['GET', 'POST'])
def editCategoryItem(url_category_id, url_item_id):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    editedItem = session.query(
        CategoryItem).filter_by(item_id=url_item_id).one()
    category = session.query(
        Category).filter_by(category_id=url_category_id).one()
    if login_session['user_id'] != category.cat_user_id:
        return "<script>function myFunction() {alert('You are not \
        authorized to edit category items to this category. Please \
        create your own category in order to edit items.');}\
        </script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.item_name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['producer']:
            editedItem.producer = request.form['producer']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('categoryItemList',
                                url_category_id=url_category_id))
    else:
        return render_template(
            'editcategoryitem.html', url_category_id=url_category_id,
            url_item_id=url_item_id, item=editedItem)


@app.route('/categories/<int:url_category_id>/<int:url_item_id>/delete',
           methods=['GET', 'POST'])
def deleteCategoryItem(url_category_id, url_item_id):
    if 'username' not in login_session:
        return redirect(url_for('showLogin'))
    category = session.query(
        Category).filter_by(category_id=url_category_id).one()
    itemToDelete = session.query(
        CategoryItem).filter_by(item_id=url_item_id).one()
    if login_session['user_id'] != category.cat_user_id:
        return "<script>function myFunction() {alert('You are not \
        authorized to delete category items to this category. Please \
        create your own category in order to delete items.');}\
        </script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('categoryItemList',
                        url_category_id=url_category_id))
    else:
        return render_template('deletecategoryitem.html', item=itemToDelete)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
