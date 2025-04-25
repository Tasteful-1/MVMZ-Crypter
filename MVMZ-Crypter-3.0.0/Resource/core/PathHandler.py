import os
import sys

class PathHandler:
    @staticmethod
    def get_base_path():
        """앱의 기본 작업 디렉토리를 반환"""
        if getattr(sys, 'frozen', False):
            # 패키징된 실행 파일일 경우
            exe_dir = os.path.dirname(sys.executable)
            return exe_dir  # 혹은 필요에 따라 상위 디렉토리 조정
        else:
            # 개발 모드일 경우 - 현재 디렉토리 사용
            return os.getcwd()  # main.py와 같은 위치

    @staticmethod
    def ensure_directories():
        """필요한 디렉토리들이 존재하는지 확인하고 생성"""
        base_path = PathHandler.get_base_path()
        directories = ['encrypted', 'decrypted', 're-encrypted']

        paths = {}
        for dir_name in directories:
            dir_path = os.path.join(base_path, dir_name)
            # 절대 경로 및 정규화된 경로로 변환
            dir_path = os.path.normpath(os.path.abspath(dir_path))
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
            paths[dir_name] = dir_path

        return paths