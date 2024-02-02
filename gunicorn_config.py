# gunicorn_config.py

import multiprocessing

# Replace 'your_django_project' with your actual Django project name
bind = "unix:/home/ec2-user/django.sock"
workers = multiprocessing.cpu_count() * 2 + 1