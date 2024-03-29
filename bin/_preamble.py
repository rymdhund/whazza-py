# setup path so we dont have to install before running
import sys
import os

path = os.path.abspath(sys.argv[0])
while os.path.dirname(path) != path:
    if os.path.exists(os.path.join(path, 'whazza', '__init__.py')):
        sys.path.insert(0, path)
        break
    path = os.path.dirname(path)
