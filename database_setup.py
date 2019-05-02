# Catalog Database Setup
import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
    '''
    Registered user data is stored in this table
    '''
    __tablename__ = 'user'

    user_id = Column(Integer, primary_key=True)
    user_name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Category(Base):
    '''
    Category data is stored in this table including id and name
    '''
    __tablename__ = 'category'

    category_id = Column(Integer, primary_key=True)
    category_name = Column(String(250), nullable=False)
    cat_user_id = Column(Integer, ForeignKey('user.user_id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
           'name': self.category_name,
           'id': self.category_id,
           'user_id': self.cat_user_id
           }


class CategoryItem(Base):
    '''
    Category's item data is stored in this table
    '''
    __tablename__ = 'category_item'

    item_name = Column(String(80), nullable=False)
    item_id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    producer = Column(String(250))
    itm_cat_id = Column(Integer, ForeignKey('category.category_id'))
    itm_user_id = Column(Integer, ForeignKey('user.user_id'))
    category = relationship(Category)
    user = relationship(User)

# We added this serialize function to be able to send
# JSON objects in a serializable format
    @property
    def serialize(self):
        return {
           'name': self.item_name,
           'description': self.description,
           'id': self.item_id,
           'price': self.price,
           'producer': self.producer,
           'user_id': self.itm_user_id,
           'category_id': self.itm_cat_id
           }


engine = create_engine('postgresql://catalog:password@localhost/catalog')
Base.metadata.create_all(engine)
