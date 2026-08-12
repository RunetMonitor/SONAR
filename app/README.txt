python3 -m venv .venv
.venv/bin/pip install pytest requests coverage
.venv/bin/python -m coverage run -m pytest test_app.py -q
.venv/bin/python -m coverage report -m --omit='config.local.py,test_*.py'
