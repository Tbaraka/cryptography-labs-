# conftest.py
# Tells pytest to include the project root in the Python path
import sys, os
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))