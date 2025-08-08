FROM python

COPY ./requirements.txt /tmp/python_requirements.txt
RUN python -m pip install -r /tmp/python_requirements.txt
RUN python -m pip install gunicorn