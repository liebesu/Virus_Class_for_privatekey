__author__ = 'liebesu'
import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
ROOTPATH = os.path.normpath(os.path.join(_current_dir, "..", ".."))
CONFPATH = os.path.normpath(os.path.join(_current_dir,"..","..","conf"))
VTAPIKEY = os.path.normpath(os.path.join(_current_dir,"..","..","vtkey"))
JSONPATH = os.path.normpath(os.path.join(_current_dir,"..","..","JSON"))
