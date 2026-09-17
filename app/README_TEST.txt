cd app
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/pip install pytest coverage
.venv/bin/python -m coverage run -m pytest test_app.py -q
.venv/bin/python -m coverage report -m --omit='config.local.py,test_*.py'
deactivate
