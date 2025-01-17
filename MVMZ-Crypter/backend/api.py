import os
import sys
import json
import shutil
import asyncio
from mvmz_core import BatchDecrypter, Decrypter
from base64 import b64encode, b64decode

class PathHandler:
	@staticmethod
	def get_base_path():
		"""앱의 기본 작업 디렉토리를 반환"""
		if getattr(sys, 'frozen', False):
			# 패키징된 실행 파일일 경우
			exe_dir = os.path.dirname(sys.executable)
			# MVMZ-crypter.exe가 있는 폴더의 두 단계 상위 디렉토리 반환
			return os.path.dirname(os.path.dirname(os.path.dirname(exe_dir)))
		else:
			# 개발 모드일 경우
			return os.path.dirname(os.path.dirname(os.getcwd()))

	@staticmethod
	def ensure_directories():
		"""필요한 디렉토리들이 존재하는지 확인하고 생성"""
		base_path = PathHandler.get_base_path()
		directories = ['encrypted', 'decrypted', 're-encrypted']

		paths = {}
		for dir_name in directories:
			dir_path = os.path.join(base_path, dir_name)
			if not os.path.exists(dir_path):
				os.makedirs(dir_path)
			paths[dir_name] = dir_path

		return paths

class MVMZBridge:
	def __init__(self):
		self.directories = PathHandler.ensure_directories()
		self.decrypter = None
		self.current_operation = None

	def send_progress(self, progress, current_file):
		"""진행 상황을 프론트엔드로 전송"""
		try:
			if isinstance(current_file, bytes):
				current_file = current_file.decode('utf-8')

			message = {
				"type": "progress",
				"data": {
					"progress": progress,
					"currentFile": current_file
				}
			}
			print(json.dumps(message, ensure_ascii=False), flush=True)
		except Exception as e:
			self.send_debug(f"[DEBUG] Error in send_progress: {str(e)}")

	def send_complete(self, result):
		"""작업 완료 메시지 전송"""
		try:
			# 폴더 이름을 Base64로 인코딩
			if "folders" in result and isinstance(result["folders"], list):
				encoded_folders = []
				for folder in result["folders"]:
					try:
						# UTF-8로 인코딩 후 Base64로 변환
						encoded = b64encode(folder.encode('utf-8')).decode('ascii')
						encoded_folders.append({
							"display": folder,  # 원본 이름
							"encoded": encoded  # Base64 인코딩된 이름
						})
					except Exception as e:
						self.send_debug(f"[DEBUG] Encoding error for folder {folder}: {str(e)}")
						continue

				result["folders"] = encoded_folders

			message = {
				"type": "complete",
				"data": result
			}

			self.send_debug(f"[DEBUG] Sending complete message: {message}")
			print(json.dumps(message), flush=True)

		except Exception as e:
			self.send_error(f"Error sending complete message: {str(e)}")

	def send_error(self, error_message):
		"""에러 메시지 전송"""
		message = {
			"type": "error",
			"data": {"message": str(error_message)}
		}
		print(json.dumps(message), flush=True)

	def send_debug(self, message: str):
		"""중요 디버그 메시지만 전송"""
		# 파일 처리 시작/완료, 에러 상황만 로깅
		if any(keyword in message for keyword in ['Starting', 'Completed', 'Error', 'Failed']):
			debug_msg = {
				"type": "debug",
				"data": {"message": message}
			}
			print(json.dumps(debug_msg), flush=True)

	def _check_folder_access(self, folder_path: str) -> bool:
		"""폴더 접근 권한을 확인합니다."""
		try:
			# 폴더가 존재하는지 확인
			if not os.path.exists(folder_path):
				self.send_debug(f"[DEBUG] 경로가 존재하지 않음: {folder_path}")
				return False

			# 읽기 권한 확인
			if not os.access(folder_path, os.R_OK):
				self.send_debug(f"[DEBUG] 읽기 권한 없음: {folder_path}")
				return False

			# 쓰기 권한 확인
			if not os.access(folder_path, os.W_OK):
				self.send_debug(f"[DEBUG] 쓰기 권한 없음: {folder_path}")
				return False

			return True

		except Exception as e:
			self.send_debug(f"[DEBUG] 권한 확인 중 오류 발생: {str(e)}")
			return False

	def _ensure_unicode_path(self, path: str) -> str:
		"""경로의 유니코드 처리를 개선"""
		try:
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
			self.send_debug(f"[DEBUG] Unicode path error: {str(e)}")
			return str(path)

	def _normalize_path(self, path: str) -> str:
		"""경로 정규화 메서드"""
		try:
			# bytes로 들어온 경우 디코딩
			if isinstance(path, bytes):
				try:
					path = path.decode('utf-8')
				except UnicodeDecodeError:
					try:
						path = path.decode('cp949')
					except UnicodeDecodeError:
						path = path.decode(sys.getfilesystemencoding())

			# 경로 정규화
			path = os.path.abspath(path)
			path = os.path.normpath(path)

			return path
		except Exception as e:
			self.send_debug(f"[DEBUG] Path normalization error: {str(e)}")
			return path

	def _process_path(self, path: str) -> str:
		"""경로 처리를 위한 통합 메서드"""
		# 절대 경로로 변환
		abs_path = os.path.abspath(path)
		# 유니코드 변환
		unicode_path = self._ensure_unicode_path(abs_path)
		# 경로 정규화
		return os.path.normpath(unicode_path)

	def _get_encrypted_filenames(self, original_filename: str, game_version: str) -> list:
			"""원본 파일명으로부터 가능한 모든 암호화된 파일명 목록을 반환"""
			name, ext = os.path.splitext(original_filename)
			ext = ext.lower()

			possible_names = []
			# MV 스타일 파일명
			if ext == '.png':
				possible_names.append(f"{name}.rpgmvp")
			elif ext == '.ogg':
				possible_names.append(f"{name}.rpgmvo")
			elif ext == '.m4a':
				possible_names.append(f"{name}.rpgmvm")

			# MZ 스타일 파일명
			if ext == '.png':
				possible_names.append(f"{name}.png_")
			elif ext == '.ogg':
				possible_names.append(f"{name}.ogg_")
			elif ext == '.m4a':
				possible_names.append(f"{name}.m4a_")

			return possible_names

	#프로세스 커맨드
	async def process_command(self, command):
		"""프론트엔드에서 받은 명령 처리"""
		try:
			cmd_type = command.get("type")
			data = command.get("data", {})

			# folders 처리 수정
			if "folders" in data:
				self.send_debug(f"[DEBUG] Processing command folders: {data['folders']}")
				selected_folders = []

				for folder_info in data["folders"]:
					try:
						if isinstance(folder_info, dict):
							# Base64로 인코딩된 이름 사용
							encoded = folder_info.get('encoded', '')
							if encoded:
								folder_name = b64decode(encoded).decode('utf-8')
								selected_folders.append(folder_name)
					except Exception as e:
						self.send_debug(f"[DEBUG] Error decoding folder: {str(e)}")
						# 디코딩 실패시 원본 이름 사용
						if isinstance(folder_info, dict) and 'name' in folder_info:
							selected_folders.append(folder_info['name'])

				data["folders"] = selected_folders

			if cmd_type == "scan_folders":
				await self.scan_folders(data)
			elif cmd_type == "find_key":
				if not data.get("folders"):
					self.send_error("No folders selected")
					return
				await self.find_encryption_key(data)
			elif cmd_type == "decrypt":
				await self.process_decryption(data)
			elif cmd_type == "encrypt":
				await self.process_encryption(data)
			elif cmd_type == "reencrypt":
				await self.process_reencryption(data)
			else:
				self.send_error(f"Unknown command type: {cmd_type}")

		except Exception as e:
			self.send_debug(f"[DEBUG] Error in process_command: {str(e)}")
			self.send_error(str(e))

	async def find_encryption_key(self, data):
		"""암호화 키 찾기"""
		try:
			folders = data.get("folders", [])

			found_keys = {}  # {key: [folders]}
			folder_key_map = {}  # {folder: key}

			for folder in folders:
				try:
					folder_path = os.path.join(self.directories['encrypted'], folder)

					if not os.path.exists(folder_path):
						self.send_debug(f"[DEBUG] Path does not exist: {folder_path}")
						continue

					# 단일 파일인 경우
					if os.path.isfile(folder_path):
						decrypter = Decrypter()
						key = decrypter.find_encryption_key_from_file(folder_path)

						if key:
							folder_key_map[folder] = key
							if key in found_keys:
								if folder not in found_keys[key]:
									found_keys[key].append(folder)
							else:
								found_keys[key] = [folder]
						continue

					# System.json 파일 찾기
					key = None
					self.send_debug(f"[DEBUG] Searching for System.json in: {folder_path}")

					for root, _, files in os.walk(folder_path):

						for file in files:
							self.send_debug(f"[DEBUG] Checking file: {file}")
							if file.lower() == "system.json":
								system_path = os.path.join(root, file)
								self.send_debug(f"[DEBUG] Found System.json at: {system_path}")
								decrypter = Decrypter()
								key = decrypter.find_encryption_key_from_file(system_path)
								self.send_debug(f"[DEBUG] Key from System.json: {key}")
								if key:
									break
						if key:
							break

					# System.json에서 키를 찾지 못한 경우 PNG 파일 검색
					if not key:
						self.send_debug(f"[DEBUG] Searching for PNG files in: {folder_path}")
						for root, _, files in os.walk(folder_path):
							self.send_debug(f"[DEBUG] Scanning directory: {root}")
							for file in files:
								if file.lower().endswith(('.rpgmvp', '.png_')):
									file_path = os.path.join(root, file)
									self.send_debug(f"[DEBUG] Checking PNG file: {file_path}")
									decrypter = Decrypter()
									key = decrypter.find_encryption_key_from_file(file_path)
									self.send_debug(f"[DEBUG] Key from PNG: {key}")
									if key:
										break
							if key:
								break

					if key:
						folder_key_map[folder] = key
						if key in found_keys:
							if folder not in found_keys[key]:
								found_keys[key].append(folder)
						else:
							found_keys[key] = [folder]
					else:
						self.send_debug(f"[DEBUG] No key found for folder: {folder}")

				except Exception as e:
					self.send_debug(f"[DEBUG] Error processing folder {folder}: {str(e)}")
					continue

			if found_keys:
				self.send_debug(f"[DEBUG] Found keys: {found_keys}")

				# 결과 정리
				ordered_keys = [
					{
						"key": key,
						"folders": folders
					}
					for key, folders in found_keys.items()
				]

				self.send_complete({
					"keys": ordered_keys
				})
			else:
				self.send_debug("[DEBUG] No keys found in any folder")
				self.send_error("No encryption key found")

		except Exception as e:
			self.send_debug(f"[DEBUG] Error in find_encryption_key: {str(e)}")
			self.send_error(str(e))

	async def process_decryption(self, data):
		"""파일 복호화 처리"""
		try:
			print("Starting decryption process...")
			folders = data.get("folders", [])
			# 경로에서 한글 처리를 위한 유니코드 변환
			folders = [self._ensure_unicode_path(folder) for folder in folders]
			provided_key = data.get("key")
			clean_folders = data.get("cleanFolders", False)

			if not folders:
				self.send_error("No folders selected")
				return

			# 1. 폴더 정리 (clean_folders 옵션)
			if clean_folders:
				for folder in folders:
					self.send_progress(0, f"[DEBUG] Cleaning folder: {folder}")
					# 소스 파일/폴더 경로
					source_path = os.path.join(self.directories['encrypted'], folder)
					self.send_progress(0, f"[DEBUG] Checking source path: {source_path}")

					# 대상 파일/폴더 경로
					target_path = os.path.join(self.directories['decrypted'], folder)

					# 파일 여부 확인
					if os.path.isfile(source_path):
						if os.path.exists(target_path):
							self.send_progress(0, f"[DEBUG] Removing existing file: {target_path}")
							try:
								os.remove(target_path)
							except Exception as e:
								self.send_progress(0, f"[DEBUG] Error removing file: {str(e)}")
					else:
						if os.path.exists(target_path):
							self.send_progress(0, f"[DEBUG] Removing existing directory: {target_path}")
							try:
								shutil.rmtree(target_path)
								os.makedirs(target_path)
							except Exception as e:
								self.send_progress(0, f"[DEBUG] Error cleaning directory: {str(e)}")
						else:
							self.send_progress(0, f"[DEBUG] Creating directory: {target_path}")
							os.makedirs(target_path)

			# 2. 전체 파일 수 계산
			print("Collecting file list...")
			total_files = 0
			for folder in folders:
				folder_path = os.path.join(self.directories['encrypted'], folder)
				if os.path.isfile(folder_path):
					total_files += 1
				else:
					for _, _, files in os.walk(folder_path):
						total_files += len(files)

			# 3. 폴더/파일별 키 찾기 및 처리
			processed_folders = 0
			processed_files = 0
			folder_keys = {}

			for folder in folders:
				try:
					folder_path = os.path.join(self.directories['encrypted'], folder)
					self.send_progress(0, f"Analyzing {folder}...")

					# 단일 파일 처리
					if os.path.isfile(folder_path):
						if provided_key:
							key = provided_key
						else:
							decrypter = Decrypter()
							key = decrypter.find_encryption_key_from_file(folder_path)

						if not key:
							self.send_error(f"No encryption key found for file: {folder}")
							return

						folder_keys[folder] = key
					else:
						# 폴더 처리 (기존 코드)
						if provided_key:
							folder_keys[folder] = provided_key
						else:
							# System.json에서 키 찾기
							found_key = None
							for root, _, files in os.walk(folder_path):
								for file in files:
									if file.lower() == 'system.json':
										system_path = os.path.join(root, file)
										decrypter = Decrypter()
										found_key = decrypter.find_encryption_key_from_file(system_path)
										if found_key:
											break
								if found_key:
									break

							# PNG 파일에서 키 찾기
							if not found_key:
								for root, _, files in os.walk(folder_path):
									for file in files:
										if file.lower().endswith(('.rpgmvp', '.png_')):
											file_path = os.path.join(root, file)
											decrypter = Decrypter()
											found_key = decrypter.find_encryption_key_from_file(file_path)
											if found_key:
												break
									if found_key:
										break

							if found_key:
								folder_keys[folder] = found_key
							else:
								self.send_error(f"No encryption key found for folder: {folder}")
								return

					# 처리 실행
					self.send_progress(0, f"Decrypting {folder}...")

					decrypter = BatchDecrypter(folder_keys[folder])
					output_dir = self.directories['decrypted']

					if os.path.isfile(folder_path):
						# 단일 파일은 decrypted 루트에 저장
						os.makedirs(output_dir, exist_ok=True)
					else:
						# 폴더는 하위 디렉토리 생성
						output_dir = os.path.join(output_dir, folder)
						os.makedirs(output_dir, exist_ok=True)

					await asyncio.get_event_loop().run_in_executor(
						None,
						lambda: decrypter.process_directory(
							self.directories['encrypted'],
							'd',
							source_folder=folder,
							custom_output_dir=output_dir
						)
					)

					# 처리된 파일 수 계산
					processed_files += 1 if os.path.isfile(folder_path) else len(
						[f for _, _, files in os.walk(folder_path) for f in files]
					)
					processed_folders += 1

					self.send_progress(
						processed_folders * 100 / len(folders),
						f"Completed: {folder} ({processed_folders}/{len(folders)} folders)"
					)

				except Exception as e:
					self.send_error(f"Error processing {folder}: {str(e)}")
					return

			# 4. 완료 처리
			self.send_complete({
				"status": "success",
				"processedFiles": processed_files
			})

		except Exception as e:
			print(f"Error in process_decryption: {str(e)}")
			self.send_error(str(e))

	async def process_directory(self, data: dict) -> None:
		"""파일 복호화 처리"""
		try:
			folders = data.get("folders", [])
			folders = [self._ensure_unicode_path(folder) for folder in folders]
			provided_key = data.get("key")
			game_version = data.get("gameVersion", "MV")
			clean_folders = data.get("cleanFolders", False)

			# 1. 폴더 정리 (clean_folders 옵션)
			if clean_folders:
				print("Cleaning output folders...")
				for folder in folders:
					### CHANGED ### - 단일 파일 처리 추가
					if os.path.isfile(os.path.join(self.directories['encrypted'], folder)):
						output_file = os.path.join(self.directories['decrypted'], folder)
						if os.path.exists(output_file):
							os.remove(output_file)
					else:
						output_folder = os.path.join(self.directories['decrypted'], folder)
						if os.path.exists(output_folder):
							print(f"Removing existing folder: {output_folder}")
							shutil.rmtree(output_folder)
							os.makedirs(output_folder)

			# 2. 전체 파일 수 계산
			print("Collecting file list...")
			total_files = 0
			for folder in folders:
				folder_path = os.path.join(self.directories['encrypted'], folder)
				folder_path = self._ensure_unicode_path(folder_path)
				if os.path.isfile(folder_path):
					total_files += 1
				else:
					for _, _, files in os.walk(folder_path):
						total_files += len(files)

			# 3. 폴더별 키 찾기 및 처리
			processed_folders = 0
			processed_files = 0
			folder_keys = {}

			for folder in folders:
				try:
					folder_path = os.path.join(self.directories['encrypted'], folder)
					folder_path = self._ensure_unicode_path(folder_path)
					self.send_progress(0, f"Analyzing {folder}...")

					### CHANGED ### - 단일 파일 키 찾기 로직 개선
					if os.path.isfile(folder_path):
						if provided_key:
							key = provided_key
						else:
							decrypter = Decrypter()
							# 파일 내용 읽기
							with open(folder_path, 'rb') as f:
								file_content = f.read()
							# 파일 확장자 검사 추가
							ext = os.path.splitext(folder.lower())[1]
							if ext in ['.rpgmvp', '.png_', '.rpgmvo', '.ogg_', '.rpgmvm', '.m4a_']:
								key = decrypter.find_encryption_key_from_file(folder_path)
								if not key:
									# PNG 파일에서 추가 시도
									key = decrypter._get_key_from_png(file_content)

						if not key:
							self.send_error(f"No encryption key found for file: {folder}")
							return

						folder_keys[folder] = key
					else:
						# 키 찾기 또는 제공된 키 사용
						if provided_key:
							folder_keys[folder] = provided_key
						else:
							# System.json에서 키 찾기
							found_key = None
							for root, _, files in os.walk(folder_path):
								for file in files:
									if file.lower() == 'system.json':
										system_path = os.path.join(root, file)
										decrypter = Decrypter()
										found_key = decrypter.find_encryption_key_from_file(system_path)
										if found_key:
											break
								if found_key:
									break

							# PNG 파일에서 키 찾기
							if not found_key:
								for root, _, files in os.walk(folder_path):
									for file in files:
										if file.lower().endswith(('.rpgmvp', '.png_')):
											file_path = os.path.join(root, file)
											decrypter = Decrypter()
											found_key = decrypter.find_encryption_key_from_file(file_path)
											if found_key:
												break
									if found_key:
										break

							if found_key:
								folder_keys[folder] = found_key
							else:
								self.send_error(f"No encryption key found for folder: {folder}")
								return

					### CHANGED ### - 파일/폴더 처리 로직 통합
					self.send_progress(0, f"Processing {folder}...")

					decrypter = BatchDecrypter(folder_keys[folder], game_version=game_version)
					output_dir = self.directories['decrypted']
					output_dir = self._ensure_unicode_path(output_dir)

					if os.path.isfile(folder_path):
						# 단일 파일은 decrypted 루트에 저장
						os.makedirs(output_dir, exist_ok=True)
					else:
						# 폴더는 하위 디렉토리 생성
						output_dir = os.path.join(output_dir, folder)
						output_dir = self._ensure_unicode_path(output_dir)
						os.makedirs(output_dir, exist_ok=True)

					await asyncio.get_event_loop().run_in_executor(
						None,
						lambda: decrypter.process_directory(
							self.directories['encrypted'],
							'd',
							source_folder=folder,
							custom_output_dir=output_dir
						)
					)

					# 처리된 파일 수 계산
					if os.path.isfile(folder_path):
						processed_files += 1
					else:
						folder_files = 0
						for root, _, files in os.walk(folder_path):
							folder_files += len(files)
						processed_files += folder_files

					processed_folders += 1
					self.send_progress(
						0,
						f"Completed: {folder} ({processed_folders}/{len(folders)} folders)"
					)

				except Exception as e:
					self.send_error(f"Error processing folder {folder}: {str(e)}")
					return

			# 4. 완료 처리
			self.send_complete({
				"status": "success",
				"processedFiles": processed_files
			})

		except Exception as e:
			print(f"Error in process_directory: {str(e)}")
			self.send_error(str(e))

	#스캔폴더
	async def scan_folders(self, data=None):
		"""폴더 및 파일 스캔"""
		try:
			# 소스 디렉토리 결정
			source = data.get('source', 'encrypted') if data else 'encrypted'
			target_dir = os.path.abspath(self.directories[source])

			if not os.path.exists(target_dir):
				os.makedirs(target_dir)
				self.send_complete({"folders": []})
				return

			items = []

			try:
				# scandir을 사용한 디렉토리 스캔
				with os.scandir(target_dir) as entries:
					for entry in entries:
						try:
							item_name = entry.name

							if entry.is_dir():
								items.append(item_name)
							elif entry.is_file():
								# 암호화할 때는 모든 이미지/오디오 파일 포함
								if source == 'decrypted':
									ext = os.path.splitext(item_name.lower())[1]
									if ext in {'.png', '.ogg', '.m4a'}:
										items.append(item_name)
								# 복호화할 때는 암호화된 파일만 포함
								else:
									ext = os.path.splitext(item_name.lower())[1]
									if ext in {'.rpgmvp', '.rpgmvo', '.rpgmvm', '.png_', '.ogg_', '.m4a_'}:
										items.append(item_name)

						except Exception as e:
							self.send_debug(f"[DEBUG] Error processing item: {str(e)}")
							continue

				# 정렬
				items.sort()

				# 단순 문자열 리스트로 전송
				self.send_complete({
					"folders": items
				})

			except Exception as e:
				self.send_debug(f"[DEBUG] Error reading directory: {str(e)}")
				self.send_error(str(e))

		except Exception as e:
			self.send_debug(f"[DEBUG] Error in scan_folders: {str(e)}")
			self.send_error(str(e))

	def _should_decrypt_file(self, filename: str) -> bool:
		"""파일이 복호화가 필요한지 확인"""
		encrypted_extensions = ['.rpgmvp', '.rpgmvo', '.rpgmvm', '.png_', '.ogg_', '.m4a_']
		return any(filename.lower().endswith(ext) for ext in encrypted_extensions)

	def _get_decrypted_filename(self, filename: str) -> str:
		"""복호화된 파일의 이름을 생성"""
		filename = filename.lower()
		if filename.endswith('.rpgmvp'):
			return filename[:-6] + 'png'
		elif filename.endswith('.rpgmvo'):
			return filename[:-6] + 'ogg'
		elif filename.endswith('.rpgmvm'):
			return filename[:-6] + 'm4a'
		elif filename.endswith(('.png_', '.ogg_', '.m4a_')):
			return filename[:-1]
		return filename

	async def process_encryption(self, data):
		"""파일 암호화 처리"""
		try:
			key = data.get("key")
			folders = data.get("folders", [])
			game_version = data.get("gameVersion", "MV")
			clean_folders = data.get("cleanFolders", False)

			if not key:
				self.send_error("Encryption key is required")
				return

			if not folders:
				self.send_error("No folders selected")
				return

			self.send_progress(0, f"[DEBUG] Base directories:")
			self.send_progress(0, f"[DEBUG] Encrypted dir: {self.directories['encrypted']}")
			self.send_progress(0, f"[DEBUG] Decrypted dir: {self.directories['decrypted']}")

			# 1. 폴더 정리 (clean_folders 옵션)
			if clean_folders:
				for folder in folders:
					self.send_progress(0, f"[DEBUG] Cleaning folder: {folder}")
					# 소스 파일/폴더 경로
					source_path = os.path.join(self.directories['decrypted'], folder)
					self.send_progress(0, f"[DEBUG] Checking source path: {source_path}")

					# 파일 여부 확인
					if os.path.isfile(source_path):
						# 가능한 모든 암호화된 파일명 확인
						encrypted_names = self._get_possible_output_filename(folder, game_version)
						self.send_progress(0, f"[DEBUG] Checking for existing encrypted files: {encrypted_names}")

						# 모든 가능한 암호화 파일 삭제
						for enc_name in encrypted_names:
							target_path = os.path.join(self.directories['encrypted'], enc_name)
							if os.path.exists(target_path):
								self.send_progress(0, f"[DEBUG] Removing existing encrypted file: {target_path}")
								try:
									os.remove(target_path)
								except Exception as e:
									self.send_progress(0, f"[DEBUG] Error removing file: {str(e)}")
					else:
						# 폴더인 경우 기존 처리 유지
						target_path = os.path.join(self.directories['encrypted'], folder)
						if os.path.exists(target_path):
							self.send_progress(0, f"[DEBUG] Removing existing directory: {target_path}")
							try:
								shutil.rmtree(target_path)
								os.makedirs(target_path)
							except Exception as e:
								self.send_progress(0, f"[DEBUG] Error cleaning directory: {str(e)}")
						else:
							self.send_progress(0, f"[DEBUG] Creating directory: {target_path}")
							os.makedirs(target_path)

			# 2. 전체 파일 수 계산
			total_files = 0
			self.send_progress(0, f"[DEBUG] Counting files:")
			for folder in folders:
				folder_path = os.path.join(self.directories['decrypted'], folder)
				self.send_progress(0, f"[DEBUG] Checking folder path: {folder_path}")
				if os.path.isfile(folder_path):
					total_files += 1
					self.send_progress(0, f"[DEBUG] Found file: {folder_path}")
				else:
					for root, _, files in os.walk(folder_path):
						total_files += len(files)
						self.send_progress(0, f"[DEBUG] Found {len(files)} files in {root}")

			# 3. 폴더별 처리
			processed_folders = 0
			processed_files = 0
			encrypter = BatchDecrypter(key, game_version=game_version)

			for folder in folders:
				try:
					self.send_progress(0, f"[DEBUG] Processing: {folder}")

					# 소스 경로와 출력 경로 설정
					decrypted_path = os.path.join(self.directories['decrypted'], folder)
					self.send_progress(0, f"[DEBUG] Source path: {decrypted_path}")

					if os.path.isfile(decrypted_path):
						# 단일 파일 처리
						self.send_progress(0, f"[DEBUG] Processing as single file")
						self.send_progress(0, f"[DEBUG] Output directory: {self.directories['encrypted']}")
						encrypter.process_directory(
							self.directories['decrypted'],
							'e',
							source_folder=folder,
							custom_output_dir=self.directories['encrypted']
						)
						processed_files += 1
					else:
						# 폴더 처리
						output_dir = os.path.join(self.directories['encrypted'], folder)
						self.send_progress(0, f"[DEBUG] Processing as directory")
						self.send_progress(0, f"[DEBUG] Output directory: {output_dir}")
						encrypter.process_directory(
							self.directories['decrypted'],
							'e',
							source_folder=folder,
							custom_output_dir=output_dir
						)
						folder_files = sum(len(files) for _, _, files in os.walk(decrypted_path))
						processed_files += folder_files

					processed_folders += 1
					self.send_progress(
						processed_folders * 100 / len(folders),
						f"Completed: {folder} ({processed_folders}/{len(folders)} folders)"
					)

				except Exception as e:
					error_msg = f"Error encrypting {folder}: {str(e)}"
					self.send_progress(0, f"[DEBUG] {error_msg}")
					self.send_error(error_msg)
					return

			# 4. 완료 처리
			self.send_complete({
				"status": "success",
				"processedFiles": processed_files
			})

		except Exception as e:
			error_msg = f"Encryption failed: {str(e)}"
			self.send_progress(0, f"[DEBUG] {error_msg}")
			self.send_error(error_msg)

	async def process_reencryption(self, data):
		"""파일 재암호화 처리"""
		try:
			new_key = data.get("key")
			folders = data.get("folders", [])
			game_version = data.get("gameVersion", "MV")
			clean_folders = data.get("cleanFolders", False)

			if not new_key:
				self.send_error("New encryption key is required")
				return

			if not folders:
				self.send_error("No folders selected")
				return

			# clean_folders가 True일 경우 정리
			if clean_folders:
				for folder in folders:
					encrypted_path = os.path.join(self.directories['encrypted'], folder)

					if os.path.isfile(encrypted_path):
						# 파일인 경우 가능한 모든 출력 파일명에 대해 청소
						possible_filenames = self._get_possible_output_filename(folder, game_version)
						for possible_name in possible_filenames:
							target_path = os.path.join(self.directories['re-encrypted'], possible_name)
							if os.path.exists(target_path):
								try:
									os.remove(target_path)
								except Exception as e:
									self.send_debug(f"[DEBUG] Error removing file {target_path}: {str(e)}")
					else:
						# 폴더인 경우
						target_path = os.path.join(self.directories['re-encrypted'], folder)
						if os.path.exists(target_path):
							try:
								shutil.rmtree(target_path)
								os.makedirs(target_path)
							except Exception as e:
								self.send_debug(f"[DEBUG] Error cleaning directory {target_path}: {str(e)}")
								continue
						else:
							try:
								os.makedirs(target_path)
							except Exception as e:
								self.send_debug(f"[DEBUG] Error creating directory {target_path}: {str(e)}")
								continue

			processed_files = 0
			folder_keys = {}

			for folder in folders:
				try:
					# 기본 경로 설정
					encrypted_path = os.path.join(self.directories['encrypted'], folder)
					encrypted_path = self._normalize_path(encrypted_path)

					if not self._check_folder_access(os.path.dirname(encrypted_path)):
						raise PermissionError(f"Access denied to path: {encrypted_path}")

					# 키 찾기 시도
					original_key = None

					if os.path.isfile(encrypted_path):
						decrypter = Decrypter()
						original_key = decrypter.find_encryption_key_from_file(encrypted_path)
						if original_key:
							self.send_debug(f"[DEBUG] Found key for file: {original_key}")
					else:
						for root, _, files in os.walk(encrypted_path):
							if not self._check_folder_access(root):
								continue

							# System.json 파일 찾기
							for file in files:
								if file.lower() == "system.json":
									system_path = os.path.join(root, file)
									decrypter = Decrypter()
									original_key = decrypter.find_encryption_key_from_file(system_path)
									if original_key:
										break

							# PNG 파일에서 키 찾기
							if not original_key:
								for file in files:
									if file.lower().endswith(('.rpgmvp', '.png_')):
										file_path = os.path.join(root, file)
										decrypter = Decrypter()
										original_key = decrypter.find_encryption_key_from_file(file_path)
										if original_key:
											break

							if original_key:
								break

					if not original_key:
						raise ValueError(f"Could not find encryption key for: {folder}")

					folder_keys[folder] = original_key

					# 임시 디렉토리 처리
					temp_dir = os.path.join(self.directories['re-encrypted'], "_temp")
					temp_dir = self._normalize_path(temp_dir)

					try:
						if os.path.exists(temp_dir):
							shutil.rmtree(temp_dir)
						os.makedirs(temp_dir)

						# 1단계: 복호화
						decrypter = BatchDecrypter(original_key)

						if os.path.isfile(encrypted_path):
							# 단일 파일 처리
							await asyncio.get_event_loop().run_in_executor(
								None,
								lambda: decrypter.process_directory(
									os.path.dirname(encrypted_path),
									'd',
									source_folder=os.path.basename(encrypted_path),
									custom_output_dir=temp_dir
								)
							)
							processed_files += 1
						else:
							# 폴더 처리 - temp_dir 직접 사용
							await asyncio.get_event_loop().run_in_executor(
								None,
								lambda: decrypter.process_directory(
									encrypted_path,
									'd',
									custom_output_dir=temp_dir
								)
							)
							processed_files += sum(len(files) for _, _, files in os.walk(encrypted_path))

						# 2단계: 새로운 키로 암호화
						encrypter = BatchDecrypter(new_key, game_version=game_version)

						# 출력 경로 설정
						output_dir = self.directories['re-encrypted']

						if os.path.isfile(encrypted_path):
							# 파일인 경우 re-encrypted 루트에 직접 저장
							await asyncio.get_event_loop().run_in_executor(
								None,
								lambda: encrypter.process_directory(
									temp_dir,
									'e',
									custom_output_dir=output_dir
								)
							)
						else:
							# 폴더인 경우 해당 폴더명으로 저장
							target_dir = os.path.join(output_dir, folder)
							# temp_dir의 내용을 target_dir로 복사하여 처리
							await asyncio.get_event_loop().run_in_executor(
								None,
								lambda: encrypter.process_directory(
									temp_dir,
									'e',
									custom_output_dir=target_dir
								)
							)

					finally:
						# 임시 디렉토리 정리
						if os.path.exists(temp_dir):
							shutil.rmtree(temp_dir)

				except PermissionError as e:
					self.send_error(f"Permission denied: {str(e)}")
					continue
				except Exception as e:
					self.send_error(f"Error processing {folder}: {str(e)}")
					continue

			# 작업 완료 보고
			self.send_complete({
				"status": "success",
				"processedFiles": processed_files,
				"folder_keys": folder_keys
			})

		except Exception as e:
			self.send_error(f"Reencryption failed: {str(e)}")

	def _decode_text(self, text):
		"""텍스트 디코딩을 처리하는 유틸리티 함수"""
		if isinstance(text, bytes):
			encodings = ['utf-8', 'cp949', 'euc-kr']
			for encoding in encodings:
				try:
					return text.decode(encoding)
				except UnicodeDecodeError:
					continue
			# 모든 인코딩 시도 실패 시 시스템 기본 인코딩 사용
			return text.decode(sys.getfilesystemencoding(), errors='replace')
		return text

	def _encode_for_json(self, text):
		"""JSON으로 보내기 전에 텍스트를 안전하게 인코딩"""
		try:
			if isinstance(text, bytes):
				return text.decode('utf-8')
			elif isinstance(text, str):
				return text.encode('utf-8').decode('utf-8')
			return str(text)
		except Exception as e:
			self.send_debug(f"[DEBUG] Encoding error: {str(e)}")
			return str(text)

	# 경로 정규화 개선을 위한 새로운 유틸리티 메소드 추가
	def _get_proper_directory_path(self, operation_type: str, item_path: str) -> str:
		"""작업 유형에 따른 적절한 디렉토리 경로 반환"""
		if operation_type == 'encrypt':
			base_dir = self.directories['decrypted']
		else:  # decrypt or find_key
			base_dir = self.directories['encrypted']

		normalized_path = self._normalize_path(os.path.join(base_dir, item_path))
		print(f"Debug - Resolved path for {operation_type}: {normalized_path}")
		return normalized_path

	async def _process_single_file(self, input_path: str, output_dir: str,
								 mod_type: str, processor: BatchDecrypter):
		"""단일 파일 처리"""
		os.makedirs(output_dir, exist_ok=True)
		await asyncio.get_event_loop().run_in_executor(
			None,
			lambda: processor.process_directory(
				os.path.dirname(input_path),
				mod_type,
				source_folder=os.path.basename(input_path),
				custom_output_dir=output_dir
			)
		)

	async def _process_folder(self, input_path: str, output_dir: str,
							mod_type: str, processor: BatchDecrypter):
		"""폴더 처리"""
		os.makedirs(output_dir, exist_ok=True)
		await asyncio.get_event_loop().run_in_executor(
			None,
			lambda: processor.process_directory(
				input_path,
				mod_type,
				custom_output_dir=output_dir
			)
		)

	def _get_possible_output_filename(self, filename: str, game_version: str = None) -> list:
		"""입력 파일명으로부터 가능한 모든 출력 파일명을 반환합니다."""
		name, ext = os.path.splitext(filename)
		ext = ext.lower()
		possible_names = []

		# 원본 파일명 추가
		possible_names.append(filename)

		# 항상 모든 가능한 형식을 포함
		if ext in ['.png', '.rpgmvp', '.png_']:
			# PNG 관련 모든 가능한 형식 추가
			possible_names.extend([
				f"{name}.png",    # 원본
				f"{name}.rpgmvp", # MV 스타일
				f"{name}.png_"    # MZ 스타일
			])
		elif ext in ['.ogg', '.rpgmvo', '.ogg_']:
			# OGG 관련 모든 가능한 형식 추가
			possible_names.extend([
				f"{name}.ogg",    # 원본
				f"{name}.rpgmvo", # MV 스타일
				f"{name}.ogg_"    # MZ 스타일
			])
		elif ext in ['.m4a', '.rpgmvm', '.m4a_']:
			# M4A 관련 모든 가능한 형식 추가
			possible_names.extend([
				f"{name}.m4a",    # 원본
				f"{name}.rpgmvm", # MV 스타일
				f"{name}.m4a_"    # MZ 스타일
			])

		# 중복 제거 후 반환
		return list(set(possible_names))

async def main():
	bridge = MVMZBridge()

	while True:
		try:
			command = await asyncio.get_event_loop().run_in_executor(
				None,
				sys.stdin.readline
			)

			if not command:
				break

			try:
				data = json.loads(command)
				await bridge.process_command(data)
			except json.JSONDecodeError:
				bridge.send_error("Invalid JSON command")

		except Exception as e:
			bridge.send_error(f"Bridge error: {str(e)}")

if __name__ == "__main__":
	asyncio.run(main())