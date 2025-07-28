import os
import sys
import json
import webview
from tkinter import Tk, filedialog
import time
import traceback
import asyncio
from .MVMZBridge import MVMZBridge
from .logger_config import setup_logging, get_logger

DEBUG_MODE = False

class WebViewAPI:
    def __init__(self):
        self.bridge = MVMZBridge()
        self.logger = get_logger('API')
        self.logger.info('WebViewAPI 초기화됨')
        self.response_data = {}
        self.current_command = None
        self.window = None
        # 콜백 등록 (debug 콜백 추가)
        self.bridge.register_callbacks(
            progress=self.on_progress,
            complete=self.on_complete,
            error=self.on_error,
            debug=self.on_debug
        )
        # 이 변수들을 인스턴스 변수로 변경
        self.path_mappings = {}
        self.result_suffix = ""

    def enable_disk_space_test(self, enable=True):
        """디스크 용량 부족 테스트 모드 활성화/비활성화"""
        try:
            self.bridge.TEST_DISK_SPACE_ERROR = enable
            mode = "활성화" if enable else "비활성화"
            self.logger.info(f"디스크 용량 부족 테스트 모드 {mode}")
            return {"success": True, "test_mode": enable}
        except Exception as e:
            self.logger.error(f"테스트 모드 설정 중 오류: {str(e)}")
            return {"error": str(e)}

    def set_window(self, window):
        self.window = window
        # window가 설정된 후 콜백 등록 (debug 콜백 추가)
        self.bridge.register_callbacks(
            progress=self.on_progress,
            complete=self.on_complete,
            error=self.on_error,
            debug=self.on_debug
        )

    def on_progress(self, data):
        """진행 상황 콜백"""
        # 필요시 window.event로 진행 상황 전달
        if self.window:
            self.window.evaluate_js(f"window.dispatchEvent(new CustomEvent('file-progress', {{detail: {json.dumps(data)}}}))")

    def on_complete(self, data):
        """작업 완료 콜백"""
        self.response_data = data.get('data', {})
        self.logger.debug(f'작업 완료 콜백 수신: {self.response_data}')

        # 프론트엔드에 완료 이벤트 발송
        if self.window:
            self.window.evaluate_js(f"window.dispatchEvent(new CustomEvent('operation-complete', {{detail: {json.dumps(data)}}}))")

    def on_error(self, data):
        """오류 콜백"""
        self.response_data = {'success': False, 'error': data.get('data', {}).get('message', '알 수 없는 오류')}
        self.logger.error(f'오류 콜백 수신: {self.response_data}')

        # 프론트엔드에 오류 이벤트 발송
        if self.window:
            self.window.evaluate_js(f"window.dispatchEvent(new CustomEvent('operation-error', {{detail: {json.dumps(data)}}}))")

    def on_debug(self, data):
        """디버그 메시지 콜백"""
        message = data.get('data', {}).get('message', '')
        self.logger.debug(f'디버그 메시지: {message}')

        # 중요 디버그 메시지만 프론트엔드로 전달
        if self.window and any(keyword in message for keyword in ['Starting', 'Completed', 'Error', 'Failed', '오류', '실패']):
            self.window.evaluate_js(f"window.dispatchEvent(new CustomEvent('debug-message', {{detail: {json.dumps(data)}}}))")

    def _execute_command(self, command_type, data, operation_name):
        """명령 실행 및 결과 반환 통합 메서드"""
        self.logger.debug(f'{operation_name} 작업 시작')

        # 경로 매핑 정보 확인
        if "folders" in data and self.path_mappings:
            self.logger.debug(f"경로 매핑 정보 확인: {self.path_mappings}")

            # 다음 코드는 경로 매핑이 제대로 적용되는지 로그로 확인
            for folder in data["folders"]:
                if folder in self.path_mappings:
                    self.logger.debug(f"폴더 '{folder}'에 대한 경로 매핑 발견: {self.path_mappings[folder]}")

        # 이미 동일한 명령이 실행 중인지 확인
        command_key = f"{command_type}:{str(data)}"
        if self.current_command == command_key:
            self.logger.warning(f'{operation_name} 작업이 이미 실행 중입니다. 중복 요청 무시.')
            return {'success': False, 'error': '이미 실행 중인 작업입니다'}

        self.current_command = command_key
        start_time = time.time()

        # 응답 데이터 초기화
        self.response_data = {}

        command = {'type': command_type, 'data': data}

        try:
            # 비동기 루프 생성
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # 비동기 작업 실행 및 직접 결과 받기
            result = loop.run_until_complete(self.bridge.process_command(command))
            loop.close()

            # 직접 결과가 있으면 반환
            if result:
                self.current_command = None
                elapsed = time.time() - start_time
                self.logger.debug(f'{operation_name} 작업 완료 (직접 결과, 소요시간: {elapsed:.2f}초)')
                return result

            # 직접 결과가 없으면 응답 대기
            wait_start = time.time()
            max_wait = 30  # 최대 30초 대기

            while not self.response_data and time.time() - wait_start < max_wait:
                time.sleep(0.1)

            if not self.response_data:
                self.logger.warning(f'{operation_name} 응답 없음 (시간 초과)')
                self.current_command = None
                return {'success': False, 'error': '응답 시간 초과'}

            elapsed = time.time() - start_time
            self.logger.debug(f'{operation_name} 작업 완료 (콜백 결과, 소요시간: {elapsed:.2f}초)')

            # 명령 완료 후 추적 변수 초기화
            self.current_command = None
            return self.response_data

        except Exception as e:
            self.logger.error(f'{operation_name} 작업 실패: {str(e)}')
            self.logger.debug(traceback.format_exc())
            self.current_command = None
            return {'success': False, 'error': str(e)}

    def scan_folders(self, source='encrypted'):
        """폴더 스캔 API"""
        self.logger.info(f'폴더 스캔 요청: source={source}')
        return self._execute_command('scan_folders', {'source': source}, '폴더 스캔')

    def clear_path_mappings(self):
        """경로 매핑 정보를 초기화합니다."""
        self.logger.info('경로 매핑 정보 초기화')
        self.path_mappings = {}
        self.result_suffix = ""

        # MVMZBridge에도 정보 초기화 전달
        if hasattr(self, 'bridge') and self.bridge:
            self.bridge.set_path_mappings({}, "")

        return {"success": True}

    def find_encryption_key(self, folders):
        """암호화 키 찾기 API"""
        self.logger.info(f'암호화 키 찾기 요청: {len(folders)}개 폴더')
        return self._execute_command('find_key', {'folders': folders}, '암호화 키 찾기')

    def decrypt_files(self, folders, key=None, clean_folders=False):
        """파일 복호화 API"""
        self.logger.info(f'파일 복호화 요청: {len(folders)}개 폴더')
        self.logger.debug(f'cleanFolders 값(인자): {clean_folders}, 타입: {type(clean_folders)}')
        data = {
            'folders': folders,
            'key': key,
            'cleanFolders': clean_folders
        }
        return self._execute_command('decrypt', data, '파일 복호화')

    def encrypt_files(self, folders, key, game_version="MV", clean_folders=False):
        """파일 암호화 API"""
        self.logger.info(f'파일 암호화 요청: {len(folders)}개 폴더, 게임버전: {game_version}')
        self.logger.debug(f'cleanFolders 값(인자): {clean_folders}, 타입: {type(clean_folders)}')
        data = {
            'folders': folders,
            'key': key,
            'gameVersion': game_version,
            'cleanFolders': clean_folders
        }
        return self._execute_command('encrypt', data, '파일 암호화')

    def reencrypt_files(self, folders, key, game_version="MV", clean_folders=False):
        """파일 재암호화 API"""
        self.logger.info(f'파일 재암호화 요청: {len(folders)}개 폴더, 게임버전: {game_version}')
        self.logger.debug(f'cleanFolders 값(인자): {clean_folders}, 타입: {type(clean_folders)}')
        data = {
            'folders': folders,
            'key': key,
            'gameVersion': game_version,
            'cleanFolders': clean_folders
        }
        return self._execute_command('reencrypt', data, '파일 재암호화')

    def get_base_path(self):
        """기본 경로 가져오기"""
        self.logger.debug('기본 경로 요청')
        try:
            from .PathHandler import PathHandler
            path = PathHandler.get_base_path()
            self.logger.debug(f'기본 경로: {path}')
            return path
        except Exception as e:
            self.logger.error(f'기본 경로 가져오기 실패: {str(e)}')
            self.logger.debug(traceback.format_exc())
            return None

    def save_logs(self, log_content, filename):
        """로그 파일 저장"""
        try:
            # 현재 실행 중인 스크립트의 디렉토리 경로 가져오기
            script_dir = os.path.dirname(os.path.abspath(__file__))

            # 로그 파일 저장 경로
            log_path = os.path.join(script_dir, '..', "logs")

            # logs 디렉토리가 없으면 생성
            if not os.path.exists(log_path):
                os.makedirs(log_path)

            # 전체 파일 경로
            full_path = os.path.join(log_path, filename)

            # 로그 내용을 파일에 저장
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(log_content)

            return {
                'success': True,
                'path': full_path
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def show_file_dialog(self, select_folder=False):
        """파일 또는 폴더 선택 대화상자를 표시합니다."""
        self.logger.info(f'파일/폴더 선택 대화상자 호출: select_folder={select_folder}')

        root = Tk()
        root.withdraw()  # GUI 창 숨기기

        try:
            if select_folder:
                # 폴더 선택 - 단일 문자열 반환
                path = filedialog.askdirectory(title="폴더 선택")
                is_directory = True

                # 단일 문자열은 그대로 반환 (리스트로 변환하지 않음)
                result_path = path
            else:
                # 파일 선택 - 튜플 반환
                path = filedialog.askopenfilenames(title="파일 선택")
                is_directory = False

                # 여러 파일은 리스트로 변환
                result_path = list(path)

            if path:  # 사용자가 취소를 누르지 않았을 경우
                self.logger.info(f'선택된 경로: {path} (폴더: {is_directory})')
                return {
                    "path": result_path,
                    "isDirectory": is_directory
                }
            else:
                self.logger.info('사용자가 선택을 취소함')
                return {"error": "선택 취소됨"}

        except Exception as e:
            self.logger.error(f'파일/폴더 선택 중 오류: {str(e)}')
            return {"error": str(e)}
        finally:
            root.destroy()

    def set_path_mappings(self, mappings, suffix=""):
        """경로 매핑 정보와 결과 파일 접미사를 설정합니다."""
        self.logger.info(f'경로 매핑 설정 시작: {len(mappings)} 항목, 접미사: {suffix}')
        self.logger.debug(f'매핑 정보 상세 내용: {mappings}')

        try:
            self.path_mappings = mappings
            self.result_suffix = suffix

            # MVMZBridge에 매핑 정보 전달
            if hasattr(self, 'bridge') and self.bridge:
                self.logger.debug('bridge 객체 존재, 매핑 정보 전달 시도')
                self.bridge.set_path_mappings(mappings, suffix)
                self.logger.info('MVMZBridge에 경로 매핑 정보 전달됨')
            else:
                self.logger.error('bridge 객체 없음 - 매핑 정보 전달 실패')

            return {"success": True}
        except Exception as e:
            self.logger.error(f'경로 매핑 설정 중 오류: {str(e)}')
            self.logger.debug(traceback.format_exc())
            return {"error": str(e)}

    def process_custom_paths(self, selected_folders, process_fn):
        """선택된 폴더 중 사용자 정의 경로를 처리"""
        self.logger.info(f'사용자 정의 경로 처리: {len(selected_folders)} 항목')
        processed_files = []

        # 접미사 목록
        possible_suffixes = ["_decrypted", "_encrypted", "_reencrypted"]

        for folder in selected_folders:
            # 사용자 정의 경로인지 확인
            if folder in self.path_mappings:
                orig_path = self.path_mappings[folder]["originalPath"]
                path_type = self.path_mappings[folder]["type"]

                # 결과 경로 생성
                if self.result_suffix:
                    if path_type == "folder":
                        # 폴더인 경우 폴더명에 접미사 추가
                        parent_dir = os.path.dirname(orig_path)
                        folder_name = os.path.basename(orig_path)

                        # 기존 접미사 제거
                        clean_folder_name = folder_name
                        for suffix in possible_suffixes:
                            if clean_folder_name.endswith(suffix):
                                clean_folder_name = clean_folder_name[:-len(suffix)]
                                break

                        result_path = os.path.join(parent_dir, f"{clean_folder_name}{self.result_suffix}")
                    else:
                        # 파일인 경우 확장자 전에 접미사 추가
                        base, ext = os.path.splitext(orig_path)

                        # 기존 접미사 제거
                        clean_base = base
                        for suffix in possible_suffixes:
                            if clean_base.endswith(suffix):
                                clean_base = clean_base[:-len(suffix)]
                                break

                        result_path = f"{clean_base}{self.result_suffix}{ext}"
                else:
                    result_path = orig_path

                self.logger.info(f'처리: {orig_path} -> {result_path}')

                # 파일 또는 폴더 처리
                if path_type == "folder":
                    # 폴더 처리 - 리팩토링된 MVMZBridge와 호환되는 처리
                    try:
                        os.makedirs(result_path, exist_ok=True)
                        processor = self.bridge.get_processor(folder)
                        if processor:
                            for root, _, files in os.walk(orig_path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    rel_path = os.path.relpath(file_path, orig_path)
                                    target_path = os.path.join(result_path, rel_path)
                                    # 파일 처리 함수 호출
                                    process_fn(file_path, target_path)
                                    processed_files.append(file_path)
                    except Exception as e:
                        self.logger.error(f"폴더 처리 중 오류: {str(e)}")
                else:
                    # 단일 파일 처리
                    try:
                        os.makedirs(os.path.dirname(result_path), exist_ok=True)
                        process_fn(orig_path, result_path)
                        processed_files.append(orig_path)
                    except Exception as e:
                        self.logger.error(f"파일 처리 중 오류: {str(e)}")

        self.logger.info(f'처리된 파일 수: {len(processed_files)}')
        return processed_files


class WebViewApp:
    def __init__(self):
        self.logger = setup_logging('MVMZ')
        self.logger.info('MVMZ 유틸리티 애플리케이션 초기화 중')
        self.window = None
        self.api = WebViewAPI()

        if hasattr(self.api, 'bridge') and self.api.bridge:
            self.logger.info('Bridge 인스턴스가 API에 올바르게 연결됨')
        else:
            self.logger.error('Bridge 인스턴스가 API에 연결되지 않음')

    def _window_closed(self):
        self.logger.info('애플리케이션 종료됨')

    def run(self):
        try:
            # HTML 파일 경로 설정
            current_dir = os.path.dirname(os.path.abspath(__file__))
            html_path = os.path.join(os.path.dirname(current_dir), 'static', 'index.html')
            icon_path = os.path.join(os.path.dirname(current_dir), 'static', 'favicon.ico')
            self.logger.info(f'HTML 경로: {html_path}')

            window_height = 980 if DEBUG_MODE else 700
            window_title = 'MVMZ-Crypter (DEBUG)' if DEBUG_MODE else 'MVMZ-Crypter'

            # 시스템 정보 로깅
            self.logger.info(f'운영체제: {sys.platform}')
            self.logger.info(f'Python 버전: {sys.version}')

            # 웹뷰 윈도우 생성
            self.logger.info('웹뷰 윈도우 생성 중')
            self.window = webview.create_window(
                title=window_title,
                url=html_path,
                js_api=self.api,
                width=1000,
                height=window_height,
                resizable=False
            )

            # API에 window 객체 설정
            self.api.set_window(self.window)

            # 종료 이벤트 연결
            self.window.events.closed += self._window_closed

            # 웹뷰 시작
            self.logger.info('웹뷰 시작')
            webview.start(debug=DEBUG_MODE)

        except Exception as e:
            self.logger.critical(f'애플리케이션 실행 중 오류 발생: {str(e)}')
            self.logger.critical(traceback.format_exc())
            raise