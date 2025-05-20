# celery_worker.py
from app import create_app
from task_defs import celery, make_celery

# Flask 앱 컨텍스트 로딩
flask_app = create_app()
make_celery(flask_app)

if __name__ == '__main__':
    # 워커 프로세스 실행: 터미널에서 python celery_worker.py 로 기동
    celery.worker_main()
