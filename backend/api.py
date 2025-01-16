import os
import sys
import json
import shutil
import asyncio
from mvmz_core import BatchDecrypter, Decrypter

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
		message = {
			"type": "progress",
			"data": {
				"progress": progress,
				"currentFile": current_file
			}
		}
		print(json.dumps(message), flush=True)

	def send_complete(self, result):
		"""작업 완료 메시지 전송"""
		message = {
			"type": "complete",
			"data": result
		}
		print(json.dumps(message), flush=True)

	def send_error(self, error_message):
		"""에러 메시지 전송"""
		message = {
			"type": "error",
			"data": {"message": str(error_message)}
		}
		print(json.dumps(message), flush=True)

	async def process_command(self, command):
		"""프론트엔드에서 받은 명령 처리"""
		try:
			cmd_type = command.get("type")
			data = command.get("data", {})

			if cmd_type == "scan_folders":
				await self.scan_folders(data)
			elif cmd_type == "find_key":
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
			print(f"Error in process_command: {str(e)}", flush=True)  # 디버깅용
			self.send_error(str(e))

	async def find_encryption_key(self, data):
		"""암호화 키 찾기"""
		try:
			folders = data.get("folders", [])
			found_keys = {}  # {key: [folders]}
			folder_key_map = {}  # {folder: key} 폴더 순서 추적용
			decrypter = Decrypter()  # Decrypter 인스턴스 생성

			for folder in folders:
				folder_path = os.path.join(self.directories['encrypted'], folder)
				self.send_progress(0, f"Searching in {folder}")

				# 먼저 System.json 파일 찾기 시도
				key = None
				for root, _, files in os.walk(folder_path):
					for file in files:
						if file.lower() == "system.json":
							system_path = os.path.join(root, file)
							key = decrypter.find_encryption_key_from_file(system_path)
							if key:
								break
					if key:
						break

				# System.json에서 키를 찾지 못한 경우 PNG 파일 검색
				if not key:
					for root, _, files in os.walk(folder_path):
						for file in files:
							if file.lower().endswith(('.rpgmvp', '.png_')):
								file_path = os.path.join(root, file)
								key = decrypter.find_encryption_key_from_file(file_path)
								if key:
									break
						if key:
							break

				if key:
					folder_key_map[folder] = key  # 폴더와 키의 매핑 저장
					if key in found_keys:
						if folder not in found_keys[key]:
							found_keys[key].append(folder)
					else:
						found_keys[key] = [folder]

				self.send_progress((folders.index(folder) + 1) * 100 / len(folders), folder)

			if found_keys:
				# 전체 폴더 리스트에서 각 폴더의 원래 위치를 맵핑
				all_folders = sorted(os.listdir(os.path.join(self.directories['encrypted'])))
				folder_indices = {folder: idx for idx, folder in enumerate(all_folders) if os.path.isdir(os.path.join(self.directories['encrypted'], folder))}

				# 키별 폴더 그룹화
				key_groups = {}  # {key: {min_index, folders[]}}

				# 각 키에 대해 폴더들과 최소 인덱스 기록
				for folder in folders:
					if folder in folder_key_map:
						key = folder_key_map[folder]
						folder_index = folder_indices.get(folder, float('inf'))

						if key not in key_groups:
							key_groups[key] = {
								'min_index': folder_index,
								'folders': []
							}
						else:
							key_groups[key]['min_index'] = min(key_groups[key]['min_index'], folder_index)

						# 폴더 추가 시 원래 순서대로 정렬
						key_groups[key]['folders'].append({
							'name': folder,
							'index': folder_index
						})

				# 각 키 그룹 내의 폴더들을 원래 인덱스 순서대로 정렬
				for key_info in key_groups.values():
					key_info['folders'].sort(key=lambda x: x['index'])
					key_info['folders'] = [f['name'] for f in key_info['folders']]

				# 최소 인덱스를 기준으로 키 정렬
				ordered_keys = [
					{
						"key": key,
						"folders": info['folders']
					}
					for key, info in sorted(key_groups.items(),
						key=lambda x: x[1]['min_index'])
				]

				self.send_complete({
					"keys": ordered_keys
				})
			else:
				self.send_error("No encryption key found")

		except Exception as e:
			self.send_error(str(e))

	async def process_decryption(self, data):
		"""파일 복호화 처리"""
		try:
			print("Starting decryption process...")
			folders = data.get("folders", [])
			provided_key = data.get("key")
			clean_folders = data.get("cleanFolders", False)

			if not folders:
				self.send_error("No folders selected")
				return

			# 1. 폴더 정리 (clean_folders 옵션)
			if clean_folders:
				print("Cleaning output folders...")
				for folder in folders:
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
				for _, _, files in os.walk(folder_path):
					total_files += len(files)

			# 3. 폴더별 키 찾기 및 처리
			processed_folders = 0
			processed_files = 0
			folder_keys = {}

			for folder in folders:
				try:
					folder_path = os.path.join(self.directories['encrypted'], folder)
					self.send_progress(0, f"Analyzing {folder}...")

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

					# 폴더 처리
					self.send_progress(0, f"Decrypting {folder}...")

					decrypter = BatchDecrypter(folder_keys[folder])
					await asyncio.get_event_loop().run_in_executor(
						None,
						lambda: decrypter.process_directory(
							self.directories['encrypted'],
							'd',
							source_folder=folder,
							custom_output_dir=os.path.join(self.directories['decrypted'], folder)
						)
					)

					# 처리된 파일 수 계산
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
			print(f"Error in process_decryption: {str(e)}")
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

			# 1. 폴더 정리 (clean_folders 옵션)
			if clean_folders:
				for folder in folders:
					output_dir = os.path.join(self.directories['encrypted'], folder)
					if os.path.exists(output_dir):
						try:
							shutil.rmtree(output_dir)
							self.send_progress(0, f"Cleaned folder: {folder}")
						except Exception as e:
							self.send_error(f"Failed to clean folder {folder}: {str(e)}")
							return

			# 2. 전체 파일 수 계산
			total_files = 0
			for folder in folders:
				folder_path = os.path.join(self.directories['decrypted'], folder)
				for _, _, files in os.walk(folder_path):
					total_files += len(files)

			# 3. 폴더별 처리
			processed_folders = 0
			processed_files = 0
			encrypter = BatchDecrypter(key, game_version=game_version)

			for folder in folders:
				try:
					self.send_progress(0, f"Encrypting {folder}...")

					# 암호화 처리
					await asyncio.get_event_loop().run_in_executor(
						None,
						lambda: encrypter.process_directory(
							self.directories['decrypted'],
							'e',
							source_folder=folder,
							custom_output_dir=os.path.join(self.directories['encrypted'], folder)
						)
					)

					# 처리된 파일 수 계산
					folder_path = os.path.join(self.directories['decrypted'], folder)
					folder_files = 0
					for _, _, files in os.walk(folder_path):
						folder_files += len(files)
					processed_files += folder_files

					processed_folders += 1
					self.send_progress(
						0,
						f"Completed: {folder} ({processed_folders}/{len(folders)} folders)"
					)

				except Exception as e:
					self.send_error(f"Error encrypting {folder}: {str(e)}")
					return

			# 4. 완료 처리
			self.send_complete({
				"status": "success",
				"processedFiles": processed_files
			})

		except Exception as e:
			self.send_error(f"Encryption failed: {str(e)}")
			return

	async def process_reencryption(self, data):
		"""파일 재암호화 처리"""
		new_key = data.get("key")  # 새로운 암호화 키
		folders = data.get("folders", [])
		game_version = data.get("gameVersion", "MV")
		clean_folders = data.get("cleanFolders", False)

		if not new_key:
			self.send_error("New encryption key is required")
			return

		if not folders:
			self.send_error("No folders selected")
			return

		try:
			# 폴더 정리
			if clean_folders:
				for folder in folders:
					output_dir = os.path.join(self.directories['re-encrypted'], folder)
					if os.path.exists(output_dir):
						try:
							shutil.rmtree(output_dir)
							self.send_progress(0, f"Cleaned folder: {folder}")
						except Exception as e:
							self.send_error(f"Failed to clean folder {folder}: {str(e)}")
							return

			# 폴더별 원본 키 찾기
			folder_keys = {}  # {folder: original_key}
			processed_folders = 0

			for folder in folders:
				folder_path = os.path.join(self.directories['encrypted'], folder)
				self.send_progress(0, f"Analyzing {folder}")

				# 1. System.json에서 키 찾기
				found_key = None
				for root, _, files in os.walk(folder_path):
					for file in files:
						if file.lower() == "system.json":
							system_path = os.path.join(root, file)
							decrypter = Decrypter()
							found_key = decrypter.find_encryption_key_from_file(system_path)
							if found_key:
								break
					if found_key:
						break

				# 2. PNG 파일에서 키 찾기
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
					self.send_progress(0, f"Found original key for {folder}: {found_key}")
				else:
					self.send_error(f"Could not find original encryption key for folder: {folder}")
					return

			# 임시 디렉토리 생성
			temp_dir = os.path.join(self.directories['re-encrypted'], "_temp")
			os.makedirs(temp_dir, exist_ok=True)

			try:
				# 폴더별 재암호화 처리
				total_files = 0
				for folder in folders:
					folder_path = os.path.join(self.directories['encrypted'], folder)
					for _, _, files in os.walk(folder_path):
						total_files += len(files)

				processed_folders = 0
				for folder in folders:
					try:
						original_key = folder_keys[folder]

						# 진행 상태 업데이트
						self.send_progress(
							0,
							f"Processing {folder}..."
						)

						# 1단계: 복호화
						temp_folder = os.path.join(temp_dir, folder)
						decrypter = BatchDecrypter(original_key)

						await asyncio.get_event_loop().run_in_executor(
							None,
							lambda: decrypter.process_directory(
								self.directories['encrypted'],
								'd',
								source_folder=folder,
								custom_output_dir=temp_folder
							)
						)

						# 2단계: 새로운 키로 암호화
						self.send_progress(
							0,
							f"Re-encrypting {folder}..."
						)

						encrypter = BatchDecrypter(new_key, game_version=game_version)
						final_output_dir = os.path.join(self.directories['re-encrypted'], folder)

						await asyncio.get_event_loop().run_in_executor(
							None,
							lambda: encrypter.process_directory(
								temp_folder,
								'e',
								source_folder='',
								custom_output_dir=final_output_dir
							)
						)

						processed_folders += 1
						self.send_progress(
							0,
							f"Completed: {folder} ({processed_folders}/{len(folders)} folders)"
						)

					except Exception as e:
						self.send_error(f"Error processing {folder}: {str(e)}")
						return

				# 작업 완료 보고
				self.send_complete({
					"status": "success",
					"folder_keys": {
						folder: {
							"original_key": orig_key,
							"new_key": new_key
						}
						for folder, orig_key in folder_keys.items()
					},
					"processedFiles": total_files  # 실제 처리된 파일 수로 변경
				})

			finally:
				# 임시 디렉토리 정리
				if os.path.exists(temp_dir):
					shutil.rmtree(temp_dir)

		except Exception as e:
			self.send_error(f"Reencryption failed: {str(e)}")
			return

	async def scan_folders(self, data=None):
		"""폴더 스캔"""
		try:
			# data가 None이면 기본값 설정
			if data is None:
				data = {}

			# source가 지정되지 않으면 encrypted를 기본값으로 사용
			source = data.get('source', 'encrypted')
			target_dir = self.directories[source]

			if not os.path.exists(target_dir):
				os.makedirs(target_dir)
				self.send_complete({"folders": []})
				return

			folders = []
			for item in os.listdir(target_dir):
				if os.path.isdir(os.path.join(target_dir, item)):
					folders.append(item)

			# 폴더명 기준으로 정렬
			folders.sort()

			self.send_complete({"folders": folders})

		except Exception as e:
			print(f"Error in scan_folders: {str(e)}", flush=True)  # 디버깅용
			self.send_error(str(e))

	# MVMZBridge 클래스 내부에 cleanFolders 메소드 추가
	def cleanFolders(self, output_dir: str, folder: str) -> None:
		"""출력 디렉토리의 기존 폴더를 정리합니다."""
		target_dir = os.path.join(output_dir, folder)
		if os.path.exists(target_dir):
			try:
				shutil.rmtree(target_dir)
			except Exception as e:
				raise

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