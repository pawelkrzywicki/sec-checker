import os
bind='0.0.0.0:8787'
workers=int(os.environ.get('WEB_WORKERS','2'))
threads=8
timeout=120
worker_tmp_dir='/tmp'
accesslog=None
