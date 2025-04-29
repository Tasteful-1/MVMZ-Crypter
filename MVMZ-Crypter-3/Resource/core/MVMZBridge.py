import os
import sys
import json
import shutil
import asyncio
import logging
import time
import threading
import traceback
from base64 import b64encode, b64decode
from dataclasses import dataclass
from typing import Optional

from .PathHandler import PathHandler
from .mvmz_core import BatchDecrypter, Decrypter
from .logger_config import get_logger


@dataclass
class FileInfo:
    """파일 정보를 저장하는 데이터 클래스"""
    path: str
    display_name: str
    type: str = "file"

    @property
    def is_file(self) -> bool:
        return self.type == "file" or os.path.isfile(self.path)

    @property
    def is_folder(self) -> bool:
        return not self.is_file


class PathProcessor:
    """경로 처리 유틸리티 클래스"""

    def __init__(self, logger):
        self.logger = logger

    def process_path(self, path: str) -> str:
        """경로 처리를 위한 통합 메서드"""
        if path is None:
            self.logger.warning("경로 값이 None으로 전달됨")
            return ""

        # 유니코드 처리
        path = self._ensure_unicode(path)

        # 절대 경로로 변환
        path = os.path.abspath(path)

        # 경로 정규화
        path = os.path.normpath(path)

        # 운영체제별 경로 구분자 처리
        if os.name == 'nt':  # Windows
            path = path.replace('/', '\\')
        else:  # Unix/Linux/Mac
            path = path.replace('\\', '/')

        return path

    def _ensure_unicode(self, path: str) -> str:
        """경로의 유니코드 처리"""
        try:
            if path is None:
                return ""

            # 유니코드 이스케이프 시퀀스 처리
            if isinstance(path, str) and '\\u' in path:
                path = bytes(path, 'utf-8').decode('unicode-escape')

            # bytes인 경우 디코딩
            if isinstance(path, bytes):
                try:
                    return path.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        return path.decode('cp949')
                    except UnicodeDecodeError:
                        return path.decode(sys.getfilesystemencoding(), errors='replace')

            return path
        except Exception as e:
            self.logger.error(f"유니코드 경로 변환 오류: {str(e)}")
            return str(path)


class MVMZProcessor:
    """MVMZ 파일 처리 기본 클래스"""

    def __init__(self, key: str, game_version: str, logger):
        self.key = key
        self.game_version = game_version
        self.logger = logger
        self.processor = BatchDecrypter(key, game_version=game_version)

    async def process_file(self, source_path: str, output_path: str, operation: str) -> bool:
        """단일 파일 처리"""
        try:
            self.logger.info(f"파일 처리: '{source_path}' -> '{output_path}'")

            # 출력 디렉토리 생성
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 파일 처리 실행
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.processor.process_single_file(
                    source_path,
                    operation,
                    custom_output_path=output_path
                )
            )

            return True
        except Exception as e:
            self.logger.error(f"파일 처리 오류: {str(e)}")
            self.logger.info(traceback.format_exc())
            return False

    async def process_directory(self, source_path: str, output_path: str, operation: str) -> bool:
        """디렉토리 처리"""
        try:
            self.logger.info(f"디렉토리 처리: '{source_path}' -> '{output_path}'")

            # 출력 디렉토리 생성
            os.makedirs(output_path, exist_ok=True)

            # 디렉토리 처리 실행
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.processor.process_directory(
                    source_path,
                    operation,
                    custom_output_dir=output_path
                )
            )

            return True
        except Exception as e:
            self.logger.error(f"디렉토리 처리 오류: {str(e)}")
            self.logger.info(traceback.format_exc())
            return False


class KeyFinder:
    """암호화 키 찾기 유틸리티 클래스"""

    def __init__(self, logger):
        self.logger = logger

    async def find_key_from_file(self, file_path: str) -> Optional[str]:
        """파일에서 암호화 키 찾기"""
        try:
            self.logger.info(f"파일에서 키 검색: '{file_path}'")

            decrypter = Decrypter()
            key = decrypter.find_encryption_key_from_file(file_path)

            if key:
                self.logger.info(f"키 발견: {key}")
                return key

            # PNG 파일 추가 검사
            ext = os.path.splitext(file_path.lower())[1]
            if ext in ['.rpgmvp', '.png_']:
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read(1024)

                    key = decrypter._get_key_from_png(file_content)
                    if key:
                        self.logger.info(f"PNG 헤더에서 키 발견: {key}")
                        return key
                except Exception as e:
                    self.logger.error(f"PNG 헤더 검사 오류: {str(e)}")

            return None
        except Exception as e:
            self.logger.error(f"키 검색 오류: {str(e)}")
            return None

    async def find_key_from_directory(self, dir_path: str) -> Optional[str]:
        """디렉토리에서 암호화 키 찾기"""
        try:
            self.logger.info(f"디렉토리에서 키 검색: '{dir_path}'")

            # 1. System.json 파일 검색
            for root, _, files in os.walk(dir_path):
                for file in files:
                    if file.lower() == "system.json":
                        system_path = os.path.join(root, file)
                        self.logger.info(f"System.json 발견: '{system_path}'")

                        key = await self.find_key_from_file(system_path)
                        if key:
                            return key

            # 2. PNG 파일 검색
            for root, _, files in os.walk(dir_path):
                for file in files:
                    if file.lower().endswith(('.rpgmvp', '.png_')):
                        file_path = os.path.join(root, file)

                        key = await self.find_key_from_file(file_path)
                        if key:
                            return key

            return None
        except Exception as e:
            self.logger.error(f"디렉토리 키 검색 오류: {str(e)}")
            return None


class MVMZBridge:
    """MVMZ 게임 파일 암호화/복호화 브리지"""

    def __init__(self):
        # 로깅 설정
        self.logger = get_logger('Bridge')
        self.logger.info("MVMZBridge 초기화 중")

        # 디렉토리 설정
        self.directories = PathHandler.ensure_directories()
        self.logger.info(f"작업 디렉토리 설정: {self.directories}")

        # 유틸리티 클래스 초기화
        self.path_processor = PathProcessor(self.logger)
        self.key_finder = KeyFinder(self.logger)

        # 상태 변수 설정
        self.path_mappings = {}
        self.result_suffix = ""
        self.processing_lock = threading.Lock()
        self.current_operation = None

        # 작업 상태 변수
        self.operation_start_time = None
        self.file_count = 0
        self.processed_count = 0

        # 콜백 함수
        self.progress_callback = None
        self.complete_callback = None
        self.error_callback = None
        self.debug_callback = None

    def register_callbacks(self, progress=None, complete=None, error=None, debug=None):
        """콜백 함수 등록"""
        self.logger.info("콜백 함수 등록")
        self.progress_callback = progress
        self.complete_callback = complete
        self.error_callback = error
        self.debug_callback = debug

    def set_path_mappings(self, mappings, suffix=""):
        """경로 매핑 정보와 결과 파일 접미사를 설정"""
        self.logger.info(f"경로 매핑 정보 설정: {len(mappings)}개 항목, 접미사: {suffix}")
        self.path_mappings = mappings
        self.result_suffix = suffix

    def send_progress(self, progress, current_file):
        """진행 상황을 프론트엔드로 전송"""
        try:
            if isinstance(current_file, bytes):
                current_file = current_file.decode('utf-8')

            # 처리된 파일 카운트 업데이트
            self.processed_count += 1

            # 진행률 계산
            if self.file_count > 0:
                percentage = min(100, (self.processed_count / self.file_count) * 100)
            else:
                percentage = progress

            # 예상 남은 시간 계산
            elapsed = time.time() - self.operation_start_time if self.operation_start_time else 0
            if self.processed_count > 0 and percentage > 0:
                estimated_total = elapsed / (percentage / 100)
                remaining = max(0, estimated_total - elapsed)
                time_info = f" (약 {remaining:.1f}초 남음)"
            else:
                time_info = ""

            message = {
                "type": "progress",
                "data": {
                    "progress": percentage,
                    "currentFile": current_file,
                    "processedCount": self.processed_count,
                    "totalCount": self.file_count,
                    "timeInfo": time_info
                }
            }

            # 로그 기록 - 10% 단위로만 기록
            if int(percentage) % 10 == 0 or percentage >= 99.9:
                self.logger.info(f"진행률: {percentage:.1f}%, 처리 중: '{current_file}'{time_info}")

            if self.progress_callback:
                self.progress_callback(message)
            else:
                print(json.dumps(message, ensure_ascii=False), flush=True)
        except Exception as e:
            self.logger.error(f"진행 정보 전송 중 오류: {str(e)}")

    def send_complete(self, result):
        """작업 완료 메시지 전송"""
        try:
            # 작업 종료 시간 기록
            if self.operation_start_time:
                elapsed = time.time() - self.operation_start_time
                self.logger.info(f"작업 완료: {self.processed_count}개 파일 처리됨 (소요시간: {elapsed:.2f}초)")
                self.operation_start_time = None

            # 결과가 None인 경우 기본 성공 응답으로 처리
            if result is None:
                result = {
                    "status": "success",
                    "processedFiles": self.processed_count
                }

            message = {
                "type": "complete",
                "data": result
            }

            if self.complete_callback:
                self.complete_callback(message)
            else:
                print(json.dumps(message), flush=True)
        except Exception as e:
            self.logger.error(f"완료 메시지 전송 오류: {str(e)}")
            self.send_error(f"완료 메시지 전송 중 오류 발생: {str(e)}")

    def send_error(self, error_message):
        """에러 메시지 전송"""
        self.logger.error(f"오류 발생: {error_message}")

        message = {
            "type": "error",
            "data": {"message": str(error_message)}
        }

        if self.error_callback:
            self.error_callback(message)
        else:
            print(json.dumps(message), flush=True)

    def send_debug(self, message: str):
        """중요 디버그 메시지 전송 및 로깅"""
        if '[DEBUG]' in message:
            message = message.replace('[DEBUG] ', '')

        # 로그 레벨 결정
        if any(keyword in message for keyword in ['Starting', 'Completed']):
            self.logger.info(message)
        elif any(keyword in message for keyword in ['Error', 'Failed', '오류', '실패']):
            self.logger.error(message)
        else:
            self.logger.info(message)

        # 중요 메시지만 프론트엔드로 전송
        if any(keyword in message for keyword in ['Starting', 'Completed', 'Error', 'Failed', '오류', '실패']):
            debug_msg = {
                "type": "debug",
                "data": {"message": message}
            }

            if self.debug_callback:
                self.debug_callback(debug_msg)
            else:
                print(json.dumps(debug_msg), flush=True)

    def _copy_special_system_files(self, source_dir, target_dir):
        """
        system 디렉토리의 특수 파일(Loading.png, Window.png)을 원본 형태로 복사
        사용자 지정 경로에서도 정상 작동하도록 구현
        """
        try:
            # 디렉토리 이름이 system인지 확인 - 경로 깊이에 상관없이 마지막 폴더명만 확인
            if os.path.basename(source_dir).lower() == 'system':
                special_files = ['Loading.png', 'Window.png']

                for filename in special_files:
                    source_file = os.path.join(source_dir, filename)
                    target_file = os.path.join(target_dir, filename)

                    # 원본 파일이 존재하는지 확인
                    if os.path.exists(source_file):
                        self.logger.info(f"특수 파일 복사: '{source_file}' -> '{target_file}'")
                        shutil.copy2(source_file, target_file)

            # 하위 디렉토리 중 system 폴더가 있는지 재귀적으로 확인
            elif os.path.isdir(source_dir):
                for item in os.listdir(source_dir):
                    item_path = os.path.join(source_dir, item)
                    if os.path.isdir(item_path) and item.lower() == 'system':
                        target_system_dir = os.path.join(target_dir, item)
                        self._copy_special_system_files(item_path, target_system_dir)

        except Exception as e:
            self.logger.error(f"특수 파일 복사 중 오류: {str(e)}")

    async def process_command(self, command):
        """프론트엔드에서 받은 명령 처리"""
        cmd_type = command.get("type")
        data = command.get("data", {})
        self.logger.debug(f'cleanFolders 값(MVMZBridge): {data.get("cleanFolders")}, 타입: {type(data.get("cleanFolders"))}')

        # 락 획득 시도
        if not self.processing_lock.acquire(blocking=False):
            self.logger.warning(f"이미 처리 중인 명령이 있습니다: {self.current_operation}")
            return {'success': False, 'error': '이미 처리 중인 명령이 있습니다'}

        try:
            self.logger.info(f"명령 처리 시작: {cmd_type}")

            # 현재 작업 설정
            self.current_operation = cmd_type

            # 작업 시작 시간 기록
            self.operation_start_time = time.time()
            self.processed_count = 0
            self.file_count = 0

            # 매핑된 폴더 정보 처리
            mapped_folders = self._prepare_folder_mappings(data)
            data["mapped_folders"] = mapped_folders

            # 출력 폴더 정리 (필요한 경우)
            if data.get("cleanFolders", False):
                await self._clean_output_folders(cmd_type, mapped_folders)

            # 명령 유형에 따른 처리
            if cmd_type == "scan_folders":
                result = await self.scan_folders(data)
                self.send_complete(result)
                return result
            elif cmd_type == "find_key":
                return await self.find_encryption_key(data)
            elif cmd_type == "decrypt":
                return await self.process_decryption(data)
            elif cmd_type == "encrypt":
                return await self.process_encryption(data)
            elif cmd_type == "reencrypt":
                return await self.process_reencryption(data)
            else:
                self.logger.error(f"알 수 없는 명령 유형: {cmd_type}")
                self.send_error(f"알 수 없는 명령 유형: {cmd_type}")
                return {"error": f"알 수 없는 명령 유형: {cmd_type}"}
        finally:
            self.current_operation = None
            self.processing_lock.release()

    def _prepare_folder_mappings(self, data):
        """폴더 매핑 정보 준비"""
        if "folders" not in data:
            return []

        folders = data.get("folders", [])
        mapped_folders = []

        for folder in folders:
            # 사용자 정의 경로 체크
            if self.path_mappings and folder in self.path_mappings:
                path_info = self.path_mappings[folder]
                original_path = path_info["originalPath"]
                path_type = path_info["type"]

                mapped_folders.append({
                    "display": folder,
                    "path": original_path,
                    "type": path_type
                })
            else:
                # 기본 경로 계산
                source_type = 'encrypted' if self.current_operation in ['decrypt', 'reencrypt', 'find_key'] else 'decrypted'
                base_path = self.directories[source_type]
                full_path = self.path_processor.process_path(os.path.join(base_path, folder))

                mapped_folders.append({
                    "display": folder,
                    "path": full_path,
                    "type": "file" if os.path.isfile(full_path) else "folder"
                })

        return mapped_folders

    async def _clean_output_folders(self, cmd_type, mapped_folders):
        """출력 폴더 정리"""
        # 작업 유형별 소스/타겟 디렉토리 결정
        if cmd_type == "reencrypt":
            target_dir = self.directories['re-encrypted']
        else:
            target_dir = self.directories['decrypted' if cmd_type == 'decrypt' else 'encrypted']

        # MVMZ 게임 관련 확장자 목록
        mvmz_extensions = ['.rpgmvp', '.rpgmvo', '.rpgmvm', '.png_', '.ogg_', '.m4a_', '.png', '.ogg', '.m4a']

        # 각 폴더별 정리
        for folder_info in mapped_folders:
            try:
                display_name = folder_info.get("display", "")
                folder_path = folder_info.get("path", "")
                folder_type = folder_info.get("type", "folder")

                # 사용자 정의 경로 처리
                if self.path_mappings and display_name in self.path_mappings and self.result_suffix:
                    path_info = self.path_mappings[display_name]
                    orig_path = path_info["originalPath"]
                    path_type = path_info.get("type", "folder")

                    if path_type == "folder":
                        # 폴더 처리
                        parent_dir = os.path.dirname(orig_path)
                        folder_name = os.path.basename(orig_path)
                        # 접미사 제거 (_decrypted, _encrypted 등)
                        clean_folder_name = self._remove_path_suffixes(folder_name)
                        target_path = os.path.join(parent_dir, f"{clean_folder_name}{self.result_suffix}")

                        # 폴더가 존재하면 삭제 후 재생성
                        if os.path.exists(target_path):
                            shutil.rmtree(target_path)
                            self.logger.info(f"기존 폴더 자동 삭제 완료: '{target_path}'")

                        os.makedirs(target_path, exist_ok=True)
                    else:
                        # 파일 처리
                        parent_dir = os.path.dirname(orig_path)
                        filename = os.path.basename(orig_path)
                        basename, _ = os.path.splitext(filename)

                        # 접미사 제거
                        clean_basename = self._remove_path_suffixes(basename)

                        # 같은 디렉토리에서 동일한 기본 이름을 가진 파일 정리
                        for existing_file in os.listdir(parent_dir):
                            existing_basename, existing_ext = os.path.splitext(existing_file)
                            clean_existing_basename = self._remove_path_suffixes(existing_basename)

                            # 기본 이름이 같고 확장자가 MVMZ 관련이며 결과 접미사가 포함된 파일 삭제
                            if (clean_existing_basename == clean_basename and
                                existing_ext.lower() in mvmz_extensions and
                                self.result_suffix in existing_basename):
                                existing_path = os.path.join(parent_dir, existing_file)
                                if os.path.isfile(existing_path):
                                    os.remove(existing_path)
                                    self.logger.info(f"기존 파일 자동 삭제: '{existing_path}' (기본명: {clean_basename})")
                else:
                    # 기본 경로 사용
                    if folder_type == "file":
                        # 파일 전체 경로에서 기본 이름만 추출 (확장자 제외)
                        filename = os.path.basename(folder_path)
                        basename, _ = os.path.splitext(filename)

                        # MVMZ 게임 관련 확장자 목록
                        mvmz_extensions = ['.rpgmvp', '.rpgmvo', '.rpgmvm', '.png_', '.ogg_', '.m4a_', '.png', '.ogg', '.m4a']

                        # 대상 디렉토리에서 같은 기본 이름을 가진 MVMZ 관련 파일 찾기
                        if os.path.exists(target_dir):
                            for existing_file in os.listdir(target_dir):
                                existing_basename, existing_ext = os.path.splitext(existing_file)

                                # 기본 이름이 같고 확장자가 MVMZ 관련 확장자인 경우 삭제
                                if existing_basename == basename and existing_ext.lower() in mvmz_extensions:
                                    existing_path = os.path.join(target_dir, existing_file)
                                    if os.path.isfile(existing_path):
                                        os.remove(existing_path)
                                        self.logger.info(f"기존 파일 자동 삭제 완료: '{existing_path}' (기본 이름 매칭: {basename})")
                        target_path = self.path_processor.process_path(os.path.join(target_dir, filename))
                    else:
                        target_path = self.path_processor.process_path(os.path.join(target_dir, display_name))

                # 경로 정리
                if target_path and os.path.exists(target_path):
                    if os.path.isdir(target_path):
                        shutil.rmtree(target_path)
                        os.makedirs(target_path)
                        self.logger.info(f"기존 폴더 자동 삭제 및 재생성 완료: '{target_path}'")
                    else:
                        os.remove(target_path)
                        self.logger.info(f"기존 파일 자동 삭제 완료: '{target_path}'")
            except Exception as e:
                self.logger.error(f"폴더 자동 정리 중 오류: {str(e)}")

    async def scan_folders(self, data=None):
        """폴더 및 파일 스캔"""
        try:
            # 소스 디렉토리 결정
            source = data.get('source', 'encrypted') if data else 'encrypted'
            base_dir = self.directories[source]
            target_dir = self.path_processor.process_path(base_dir)

            self.logger.info(f"폴더 스캔 시작: '{target_dir}' (소스: {source})")

            if not os.path.exists(target_dir):
                self.logger.warning(f"디렉토리가 존재하지 않아 생성합니다: '{target_dir}'")
                os.makedirs(target_dir)
                return {"folders": []}

            items = []
            scan_count = 0

            # scandir을 사용한 디렉토리 스캔
            with os.scandir(target_dir) as entries:
                for entry in entries:
                    scan_count += 1
                    try:
                        item_name = entry.name

                        if entry.is_dir():
                            items.append(item_name)
                        elif entry.is_file():
                            # 암호화/복호화 가능 파일만 포함
                            ext = os.path.splitext(item_name.lower())[1]
                            if source == 'decrypted' and ext in {'.png', '.ogg', '.m4a'}:
                                items.append(item_name)
                            elif source == 'encrypted' and ext in {'.rpgmvp', '.rpgmvo', '.rpgmvm', '.png_', '.ogg_', '.m4a_'}:
                                items.append(item_name)
                    except Exception as e:
                        self.logger.error(f"항목 처리 오류: '{entry.name if hasattr(entry, 'name') else 'unknown'}' - {str(e)}")
                        continue

            # 정렬
            items.sort()

            self.logger.info(f"폴더 스캔 완료: {len(items)}개 항목 발견 (검사 항목: {scan_count}개)")

            return {"folders": items}
        except Exception as e:
            self.logger.error(f"scan_folders 오류: {str(e)}")
            self.send_error(str(e))
            return {"folders": []}

    async def find_encryption_key(self, data):
        """암호화 키 찾기"""
        try:
            folders = data.get("folders", [])
            mapped_folders = data.get("mapped_folders", [])

            if not folders:
                self.logger.error("선택된 폴더 없음")
                self.send_error("선택된 폴더가 없습니다")
                return {"error": "선택된 폴더가 없습니다"}

            found_keys = {}  # {key: [folders]}
            folder_key_map = {}  # {folder: key}

            # 폴더별 키 찾기
            for folder_info in mapped_folders:
                display_name = folder_info.get("display", "")
                folder_path = folder_info.get("path", "")
                folder_type = folder_info.get("type", "folder")

                self.logger.info(f"폴더 '{display_name}' 처리 중")

                try:
                    # 파일 또는 폴더 구분 처리
                    if folder_type == "file" or os.path.isfile(folder_path):
                        key = await self.key_finder.find_key_from_file(folder_path)
                    else:
                        key = await self.key_finder.find_key_from_directory(folder_path)

                    # 키 발견 시 처리
                    if key:
                        self.logger.info(f"'{display_name}'에서 키 발견: {key}")
                        folder_key_map[display_name] = key

                        if key in found_keys:
                            if display_name not in found_keys[key]:
                                found_keys[key].append(display_name)
                        else:
                            found_keys[key] = [display_name]
                    else:
                        self.logger.warning(f"'{display_name}'에서 키를 찾을 수 없음")
                except Exception as e:
                    self.logger.error(f"'{display_name}' 처리 중 오류: {str(e)}")
                    continue

            # 결과 처리
            if found_keys:
                ordered_keys = [
                    {
                        "key": key,
                        "folders": folders
                    }
                    for key, folders in found_keys.items()
                ]

                result = {"keys": ordered_keys}
                self.send_complete(result)
                return result
            else:
                self.logger.warning("어떤 폴더에서도 키를 찾지 못함")
                self.send_error("암호화 키를 찾을 수 없습니다")
                return {"error": "암호화 키를 찾을 수 없습니다"}
        except Exception as e:
            self.logger.error(f"find_encryption_key 오류: {str(e)}")
            self.send_error(str(e))
            return {"error": str(e)}

    async def process_decryption(self, data):
        """파일 복호화 처리"""
        try:
            folders = data.get("folders", [])
            mapped_folders = data.get("mapped_folders", [])
            provided_key = data.get("key")

            if not folders:
                self.logger.error("선택된 폴더 없음")
                self.send_error("선택된 폴더가 없습니다")
                return

            # 전체 파일 수 계산
            self.file_count = await self._count_total_files(mapped_folders)

            # 각 폴더별 처리
            processed_files = 0

            for folder_info in mapped_folders:
                try:
                    display_name = folder_info.get("display", "")
                    folder_path = folder_info.get("path", "")
                    folder_type = folder_info.get("type", "folder")

                    self.logger.info(f"폴더 처리 중: '{display_name}'")

                    # 1. 키 찾기 또는 제공된 키 사용
                    if provided_key:
                        key = provided_key
                    else:
                        if folder_type == "file" or os.path.isfile(folder_path):
                            key = await self.key_finder.find_key_from_file(folder_path)
                        else:
                            key = await self.key_finder.find_key_from_directory(folder_path)

                    if not key:
                        error_msg = f"'{display_name}'에서 암호화 키를 찾을 수 없음"
                        self.logger.error(error_msg)
                        self.send_error(error_msg)
                        return

                    # 2. 출력 경로 결정
                    output_path = self._determine_output_path(display_name, folder_path, folder_type, "decrypt")

                    # 3. 복호화 처리
                    processor = MVMZProcessor(key, "MV", self.logger)

                    if folder_type == "file" or os.path.isfile(folder_path):
                        success = await processor.process_file(
                            folder_path,
                            output_path,
                            'd'
                        )
                        if success:
                            processed_files += 1
                    else:
                        success = await processor.process_directory(
                            folder_path,
                            output_path,
                            'd'
                        )
                        if success:
                            dir_files = sum(len(files) for _, _, files in os.walk(folder_path))
                            processed_files += dir_files

                    self.send_progress(
                        0,  # 진행률은 파일 카운트 기반으로 자동 계산됨
                        f"완료: '{display_name}'"
                    )

                except Exception as e:
                    error_msg = f"'{display_name}' 처리 중 오류: {str(e)}"
                    self.logger.error(error_msg)
                    self.send_error(error_msg)
                    return

            # 완료 처리
            result = {
                "status": "success",
                "processedFiles": processed_files
            }
            self.send_complete(result)
            return result
        except Exception as e:
            self.logger.error(f"process_decryption 오류: {str(e)}")
            self.send_error(str(e))
            return {"error": str(e)}

    async def process_encryption(self, data):
        """파일 암호화 처리"""
        try:
            folders = data.get("folders", [])
            mapped_folders = data.get("mapped_folders", [])
            key = data.get("key")
            game_version = data.get("gameVersion", "MV")

            if not key:
                self.logger.error("암호화 키가 제공되지 않음")
                self.send_error("암호화 키가 필요합니다")
                return

            if not folders:
                self.logger.error("선택된 폴더 없음")
                self.send_error("선택된 폴더가 없습니다")
                return

            # 전체 파일 수 계산
            self.file_count = await self._count_total_files(mapped_folders)

            # 각 폴더별 처리
            processed_files = 0
            processor = MVMZProcessor(key, game_version, self.logger)

            for folder_info in mapped_folders:
                try:
                    display_name = folder_info.get("display", "")
                    folder_path = folder_info.get("path", "")
                    folder_type = folder_info.get("type", "folder")

                    self.logger.info(f"폴더 처리 중: '{display_name}'")

                    # 출력 경로 결정
                    output_path = self._determine_output_path(display_name, folder_path, folder_type, "encrypt", game_version)

                    # 암호화 처리
                    if folder_type == "file" or os.path.isfile(folder_path):
                        success = await processor.process_file(
                            folder_path,
                            output_path,
                            'e'
                        )
                        if success:
                            processed_files += 1
                    else:
                        success = await processor.process_directory(
                            folder_path,
                            output_path,
                            'e'
                        )
                        if success:
                            dir_files = sum(len(files) for _, _, files in os.walk(folder_path))
                            processed_files += dir_files

                            if folder_type == "folder":
                                self._copy_special_system_files(folder_path, output_path)

                    self.send_progress(
                        0,  # 진행률은 파일 카운트 기반으로 자동 계산됨
                        f"완료: '{display_name}'"
                    )
                except Exception as e:
                    error_msg = f"'{display_name}' 암호화 중 오류: {str(e)}"
                    self.logger.error(error_msg)
                    self.send_error(error_msg)
                    return {"error": str(e)}

            # 완료 처리
            result = {
                "status": "success",
                "processedFiles": processed_files
            }
            self.send_complete(result)
            return result
        except Exception as e:
            self.logger.error(f"process_encryption 오류: {str(e)}")
            self.send_error(str(e))
            return {"error": str(e)}

    async def process_reencryption(self, data):
        """파일 재암호화 처리"""
        try:
            folders = data.get("folders", [])
            mapped_folders = data.get("mapped_folders", [])
            new_key = data.get("key")
            game_version = data.get("gameVersion", "MV")
            self.logger.info(f"재암호화 게임 버전: {game_version}")

            if not new_key:
                self.logger.error("새 암호화 키가 제공되지 않음")
                self.send_error("새 암호화 키가 필요합니다")
                return

            if not folders:
                self.logger.error("선택된 폴더 없음")
                self.send_error("선택된 폴더가 없습니다")
                return

            # 전체 파일 수 계산
            self.file_count = await self._count_total_files(mapped_folders)

            # 임시 디렉토리
            temp_dir = self.path_processor.process_path(os.path.join(self.directories['re-encrypted'], "_temp"))

            # 각 폴더별 처리
            processed_files = 0
            folder_keys = {}

            for folder_info in mapped_folders:
                try:
                    display_name = folder_info.get("display", "")
                    folder_path = folder_info.get("path", "")
                    folder_type = folder_info.get("type", "folder")

                    self.logger.info(f"폴더 처리 중: '{display_name}'")

                    # 1. 원본 키 찾기
                    if folder_type == "file" or os.path.isfile(folder_path):
                        original_key = await self.key_finder.find_key_from_file(folder_path)
                    else:
                        original_key = await self.key_finder.find_key_from_directory(folder_path)

                    # 키가 없는 경우 새 키를 원본 키로 사용
                    if not original_key:
                        original_key = new_key
                        self.logger.info(f"원본 키를 찾을 수 없어 새 키 사용: {new_key}")

                    folder_keys[display_name] = original_key

                    # 2. 임시 디렉토리 설정
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                    os.makedirs(temp_dir)

                    # 3. 복호화 처리
                    decrypter = MVMZProcessor(original_key, game_version, self.logger)

                    if folder_type == "file" or os.path.isfile(folder_path):
                        # 복호화된 파일명 계산
                        orig_filename = os.path.basename(folder_path)
                        decrypted_filename = self._get_decrypted_filename(orig_filename)
                        temp_file_path = os.path.join(temp_dir, decrypted_filename)
                        await decrypter.process_file(folder_path, temp_file_path, 'd')
                    else:
                        await decrypter.process_directory(folder_path, temp_dir, 'd')

                    # 4. 출력 경로 결정
                    if folder_type == "file" or os.path.isfile(folder_path):
                        # 원본 파일명에서 정보 추출
                        orig_filename = os.path.basename(folder_path)

                        # 사용자 정의 경로 처리
                        if display_name in self.path_mappings and self.result_suffix:
                            path_info = self.path_mappings[display_name]
                            orig_path = path_info["originalPath"]

                            # 파일 경로 처리
                            parent_dir = os.path.dirname(orig_path)
                            base_filename = os.path.basename(orig_path)
                            base, ext = os.path.splitext(base_filename)

                            # 접미사 중복 방지
                            clean_base = self._remove_path_suffixes(base)

                            # 복호화된 파일명 구하기 (소문자 변환 없이)
                            decrypted_filename = self._get_decrypted_filename(orig_filename)
                            _, original_ext = os.path.splitext(decrypted_filename)

                            # 게임 버전에 맞는 암호화 확장자 결정
                            new_ext = self._get_encrypted_ext(original_ext, game_version)

                            # 최종 출력 파일명 생성 (원래 대소문자 유지, 접미사 추가)
                            output_path = os.path.join(parent_dir, f"{clean_base}{self.result_suffix}{new_ext}")
                        else:
                            # 기본 경로 사용 (현재 방식 유지)
                            decrypted_filename = self._get_decrypted_filename(orig_filename)
                            decrypted_basename = os.path.splitext(decrypted_filename)[0]
                            original_ext = os.path.splitext(decrypted_filename)[1]

                            # 게임 버전에 맞는 암호화 확장자 결정
                            new_ext = self._get_encrypted_ext(original_ext, game_version)

                            # 최종 출력 파일명 생성
                            output_filename = f"{decrypted_basename}{new_ext}"
                            output_path = os.path.join(self.directories['re-encrypted'], output_filename)
                    else:
                        # 폴더인 경우는 기존 방식 유지
                        output_path = self._determine_output_path(display_name, folder_path, folder_type, "reencrypt", game_version)

                    # 5. 재암호화 처리
                    encrypter = MVMZProcessor(new_key, game_version, self.logger)
                    self.logger.info(f"encrypter: {new_key},{game_version}")
                    if folder_type == "file" or os.path.isfile(folder_path):
                        # 임시 디렉토리에서 파일 찾기
                        temp_files = os.listdir(temp_dir)
                        self.logger.info(f"temp_files: {temp_files}")
                        if temp_files:
                            # 임시 파일 경로
                            temp_file_path = os.path.join(temp_dir, temp_files[0])

                            # 출력 경로 분석
                            output_dir = os.path.dirname(output_path)
                            output_base = os.path.splitext(os.path.basename(output_path))[0]

                            # 임시 파일 확장자 확인 (복호화된 상태)
                            _, temp_ext = os.path.splitext(temp_file_path)
                            temp_ext = temp_ext.lower()

                            # 게임 버전에 따른 확장자 결정
                            if game_version == "MV":
                                if temp_ext == '.png':
                                    new_ext = '.rpgmvp'
                                elif temp_ext == '.ogg':
                                    new_ext = '.rpgmvo'
                                elif temp_ext == '.m4a':
                                    new_ext = '.rpgmvm'
                                else:
                                    new_ext = temp_ext
                            else:  # MZ
                                if temp_ext == '.png':
                                    new_ext = '.png_'
                                elif temp_ext == '.ogg':
                                    new_ext = '.ogg_'
                                elif temp_ext == '.m4a':
                                    new_ext = '.m4a_'
                                else:
                                    new_ext = temp_ext

                            # 수정된 출력 경로
                            final_output_path = os.path.join(output_dir, f"{output_base}{new_ext}")
                            self.logger.info(f"final_output_path: {final_output_path}")

                            # 임시 파일 암호화
                            await encrypter.process_file(temp_file_path, final_output_path, 'e')
                            processed_files += 1
                    else:
                        await encrypter.process_directory(temp_dir, output_path, 'e')
                        dir_files = sum(len(files) for _, _, files in os.walk(folder_path))
                        processed_files += dir_files
                        if folder_type == "folder":
                            self._copy_special_system_files(folder_path, output_path)

                    self.send_progress(
                        0,  # 진행률은 파일 카운트 기반으로 자동 계산됨
                        f"완료: '{display_name}'"
                    )
                except Exception as e:
                    error_msg = f"'{display_name}' 재암호화 중 오류: {str(e)}"
                    self.logger.error(error_msg)
                    self.send_error(error_msg)
                    return {"error": str(e)}
                finally:
                    # 임시 디렉토리 정리
                    if os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)

            # 완료 처리
            result = {
                "status": "success",
                "processedFiles": processed_files,
                "folder_keys": folder_keys
            }
            self.send_complete(result)
            return result
        except Exception as e:
            self.logger.error(f"process_reencryption 오류: {str(e)}")
            self.send_error(str(e))
            return {"error": str(e)}

    async def _count_total_files(self, folder_items):
        """총 파일 수 계산"""
        total_files = 0
        for folder_info in folder_items:
            folder_path = folder_info.get("path", "")
            folder_type = folder_info.get("type", "folder")

            if folder_type == "file" or os.path.isfile(folder_path):
                total_files += 1
            else:
                for _, _, files in os.walk(folder_path):
                    total_files += len(files)

        self.logger.info(f"처리할 총 파일 수: {total_files}개")
        return total_files

    def _determine_output_path(self, display_name, folder_path, folder_type, operation, game_version=None):
        """작업 유형에 따른 출력 경로 결정"""
        # 작업 유형별 기본 출력 디렉토리
        if operation == "decrypt":
            base_output_dir = self.directories['decrypted']
            file_transform = self._get_decrypted_filename
        elif operation == "encrypt":
            base_output_dir = self.directories['encrypted']
            file_transform = lambda f: self._get_encrypted_filename(f, game_version)
        else:  # reencrypt
            base_output_dir = self.directories['re-encrypted']
            file_transform = lambda f: self._get_encrypted_filename(f, game_version)

        # 사용자 정의 경로 처리
        if display_name in self.path_mappings and self.result_suffix:
            path_info = self.path_mappings[display_name]
            orig_path = path_info["originalPath"]
            path_type = path_info.get("type", "folder")

            if path_type == "folder":
                # 폴더인 경우 접미사 추가
                parent_dir = os.path.dirname(orig_path)
                folder_name = os.path.basename(orig_path)

                # 접미사 중복 방지
                clean_folder_name = self._remove_path_suffixes(folder_name)

                output_path = self.path_processor.process_path(
                    os.path.join(parent_dir, f"{clean_folder_name}{self.result_suffix}")
                )
            else:
                # 파일인 경우 확장자 변환 처리
                parent_dir = os.path.dirname(orig_path)
                base_filename = os.path.basename(orig_path)
                base, ext = os.path.splitext(base_filename)

                # 접미사 중복 방지
                clean_base = self._remove_path_suffixes(base)

                # 확장자 변환
                if operation == "decrypt":
                    new_ext = self._get_decrypted_ext(ext)
                else:
                    new_ext = self._get_encrypted_ext(ext, game_version)

                output_path = os.path.join(parent_dir, f"{clean_base}{self.result_suffix}{new_ext}")
        else:
            # 기본 경로 사용
            if folder_type == "file" or os.path.isfile(folder_path):
                # 파일인 경우 파일명만 변환
                filename = os.path.basename(folder_path)
                new_filename = file_transform(filename)
                output_path = os.path.join(base_output_dir, new_filename)
            else:
                # 폴더인 경우 하위 디렉토리 생성
                output_path = os.path.join(base_output_dir, display_name)

        # 출력 디렉토리 생성
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        return output_path

    def _remove_path_suffixes(self, path_str):
        """접미사 중복 방지를 위한 경로 접미사 제거"""
        for suffix in ["_decrypted", "_encrypted", "_reencrypted"]:
            if path_str.endswith(suffix):
                return path_str[:-len(suffix)]
        return path_str

    def _get_decrypted_filename(self, filename):
        """복호화된 파일의 이름을 생성"""

        if filename.lower().endswith('.rpgmvp'):
            return filename[:-6] + 'png'
        elif filename.lower().endswith('.rpgmvo'):
            return filename[:-6] + 'ogg'
        elif filename.lower().endswith('.rpgmvm'):
            return filename[:-6] + 'm4a'
        elif filename.lower().endswith(('.png_', '.ogg_', '.m4a_')):
            return filename[:-1]

        return filename

    def _get_encrypted_filename(self, filename, game_version):
        """암호화된 파일의 이름을 생성"""
        name, ext = os.path.splitext(filename)
        ext = ext.lower()

        if game_version == "MV":
            if ext == '.png':
                return f"{name}.rpgmvp"
            elif ext == '.ogg':
                return f"{name}.rpgmvo"
            elif ext == '.m4a':
                return f"{name}.rpgmvm"
        else:  # MZ
            if ext == '.png':
                return f"{name}.png_"
            elif ext == '.ogg':
                return f"{name}.ogg_"
            elif ext == '.m4a':
                return f"{name}.m4a_"

        return filename

    def _get_decrypted_ext(self, ext):
        """복호화된 파일의 확장자 결정"""
        ext = ext.lower()

        if ext == '.rpgmvp' or ext == '.png_':
            return '.png'
        elif ext == '.rpgmvo' or ext == '.ogg_':
            return '.ogg'
        elif ext == '.rpgmvm' or ext == '.m4a_':
            return '.m4a'

        return ext

    def _get_encrypted_ext(self, ext, game_version):
        """암호화된 파일의 확장자 결정"""
        ext = ext.lower()

        if game_version == "MV":
            if ext == '.png':
                return '.rpgmvp'
            elif ext == '.ogg':
                return '.rpgmvo'
            elif ext == '.m4a':
                return '.rpgmvm'
        else:  # MZ
            if ext == '.png':
                return '.png_'
            elif ext == '.ogg':
                return '.ogg_'
            elif ext == '.m4a':
                return '.m4a_'

        return ext