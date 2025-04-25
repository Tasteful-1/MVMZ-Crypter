import os
import logging
import time
import glob

# 싱글톤 패턴으로 로거 관리
_loggers = {}

def cleanup_old_logs(log_dir, max_log_count=100):
    """
    오래된 로그 파일을 정리하는 함수
    """
    # 로그 파일 목록 가져오기 (mvmz_*.log 패턴 매칭)
    log_files = glob.glob(os.path.join(log_dir, 'mvmz_*.log'))

    # 파일 갯수가 제한을 초과하면 정리
    if len(log_files) > max_log_count:
        # 파일을 수정일 기준으로 정렬 (오래된 것부터)
        log_files.sort(key=lambda x: os.path.getmtime(x))

        # 제한을 초과하는 오래된 파일 삭제
        files_to_delete = log_files[:len(log_files) - max_log_count]
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                print(f"오래된 로그 파일 삭제됨: {os.path.basename(file_path)}")
            except Exception as e:
                print(f"로그 파일 삭제 실패: {os.path.basename(file_path)}, 오류: {str(e)}")

def setup_logging(name='MVMZ', level=logging.DEBUG, max_log_count=100):
    """
    중앙 집중식 로깅 설정 함수
    """
    # 이미 설정된 로거가 있으면 재사용
    if name in _loggers:
        return _loggers[name]

    # 로그 디렉토리 생성
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(base_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    # 오래된 로그 파일 정리
    cleanup_old_logs(log_dir, max_log_count)

    # 로그 파일 이름 (공통 타임스탬프 사용)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f'mvmz_{timestamp}.log')

    # 루트 로거 설정
    root_logger = logging.getLogger(name)

    # 이미 핸들러가 있는지 확인 (중복 방지)
    if not root_logger.handlers:
        root_logger.setLevel(level)

        # 파일 핸들러
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        file_handler.setFormatter(file_formatter)

        # 콘솔 핸들러
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        console_handler.setFormatter(console_formatter)

        # 핸들러 추가
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

        print(f"로깅 시스템 초기화 완료: {log_file}")
        print(f"최대 로그 파일 수: {max_log_count}개 (초과시 오래된 파일 자동 삭제)")

    # 로거 캐싱
    _loggers[name] = root_logger
    return root_logger

def get_logger(module_name):
    """
    하위 모듈용 로거 가져오기
    """
    # 메인 로거가 없으면 생성
    if 'MVMZ' not in _loggers:
        setup_logging('MVMZ')

    # 하위 로거 생성 (계층 구조 활용)
    logger = logging.getLogger(f'MVMZ.{module_name}')
    return logger