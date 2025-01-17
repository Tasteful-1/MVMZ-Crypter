import os
import shutil
from typing import Optional, Callable
from dataclasses import dataclass
import time
import sys
import json

os.environ["PYTHONOPTIMIZE"] = "2"

CURRENT_VERSION = "2.0.3"

@dataclass
class RPGFile:
	"""RPG Maker 파일을 표현하는 클래스"""
	name: str
	extension: str
	content: Optional[bytes] = None
	file: Optional[bytes] = None

class Decrypter:
	"""파일 암호화/복호화를 처리하는 클래스"""
	DEFAULT_HEADER_LEN = 16
	DEFAULT_SIGNATURE = "5250474d56000000"
	DEFAULT_VERSION = "000301"
	DEFAULT_REMAIN = "0000000000"
	PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
	PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

	def __init__(self, encryption_key: Optional[str] = None):
		self.encrypt_code = encryption_key
		self.ignore_fake_header = False
		self.header_len = self.DEFAULT_HEADER_LEN
		self.signature = self.DEFAULT_SIGNATURE
		self.version = self.DEFAULT_VERSION
		self.remain = self.DEFAULT_REMAIN
		self.encryption_code_array = self.split_encryption_code()

	def split_encryption_code(self) -> list:
		if not self.encrypt_code:
			return []
		return [self.encrypt_code[i:i+2] for i in range(0, len(self.encrypt_code), 2)]

	def modify_file(self, rpg_file: RPGFile, mod_type: str, callback: Callable):
		try:
			if rpg_file.file is None:
				raise Exception("No file content provided")

			# 파일명에 한글이 포함된 경우를 위한 처리
			if isinstance(rpg_file.name, bytes):
				rpg_file.name = rpg_file.name.decode('utf-8')

			file_content = rpg_file.file

			if mod_type == 'e':
				rpg_file.content = self.encrypt(file_content)
			elif mod_type == 'd':
				rpg_file.content = self.decrypt(file_content)
			else:
				raise ValueError("Unsupported modification type")

			callback(rpg_file, None)

		except Exception as e:
			callback(rpg_file, e)

	def encrypt(self, file_content: bytes) -> bytes:
		if not file_content:
			raise Exception("Empty file")

		fake_header = self.build_fake_header()
		encrypted_content = self.xor_bytes(file_content)
		return fake_header + encrypted_content

	def decrypt(self, file_content: bytes) -> bytes:
		if not file_content:
			raise Exception("Empty file")

		header_len = self.header_len
		file_content = file_content[header_len:]
		return self.xor_bytes(file_content)

	def xor_bytes(self, content: bytes) -> bytes:
		if not content:
			return content

		result = bytearray(content)
		for i in range(min(self.header_len, len(content))):
			result[i] ^= int(self.encryption_code_array[i % len(self.encryption_code_array)], 16)
		return bytes(result)

	def find_encryption_key_from_file(self, filepath: str) -> Optional[str]:
		"""단일 암호화된 파일에서 암호화 키를 추출합니다."""
		try:
			with open(filepath, 'rb') as f:
				file_content = f.read()

				if len(file_content) < self.DEFAULT_HEADER_LEN * 2:
					return None

				# PNG 파일인 경우의 키 추출 시도
				if filepath.lower().endswith(('.rpgmvp', '.png_')):
					key = self._get_key_from_png(file_content)
					if key:
						return key
					else:
						print("PNG 키 추출 실패")  # 디버깅 로그

				# PNG 추출 실패시 다른 메서드 시도
				print("다른 방식의 키 추출 시도...")  # 디버깅 로그

				# 다른 메서드들 시도
				methods = [
					(self._search_key_in_json, "JSON 검색"),
					(self._try_decrypt_with_headers, "헤더 분석")
				]

				for method, name in methods:
					key = method(file_content)
					if key:
						return key

			return None

		except Exception as e:
			self.send_debug(f"Key extraction failed: {str(e)}")
			return None

	def _get_key_from_png(self, file_content: bytes) -> Optional[str]:
		"""PNG 파일에서 암호화 키를 추출합니다."""
		try:
			header_len = self.DEFAULT_HEADER_LEN

			# 첫 번째 헤더 영역을 건너뛰고 두 번째 헤더 영역 추출
			encrypted_header = file_content[header_len:header_len * 2]

			# 표준 PNG 헤더 (처음 16바이트)
			png_header = bytes([
				0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
				0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52
			])

			# 추출된 키가 16진수로만 구성되어 있는지 확인하는 함수 추가
			if len(encrypted_header) < len(png_header):
				return None

			# XOR 연산으로 키 추출
			key_bytes = bytearray()
			for i in range(len(png_header)):
				key_byte = encrypted_header[i] ^ png_header[i]
				key_bytes.append(key_byte)

			# 바이트를 16진수 문자열로 변환
			key = ''.join([f'{b:02X}' for b in key_bytes])

			# 키 검증
			if not self._check_hex_chars(key):
				return None

			# 추출된 키로 테스트 복호화 수행
			decrypted_test = self._test_decrypt_png(encrypted_header, key)
			if decrypted_test.startswith(png_header[:8]):  # PNG 시그니처 확인
				return key

			return None

		except Exception as e:
			self.send_debug(f"PNG 키 추출 중 오류: {e}")
			return None

	def send_debug(self, message: str):
		"""디버그 메시지를 프론트엔드로 전송"""
		debug_msg = {
			"type": "debug",
			"data": {"message": message}
		}
		print(json.dumps(debug_msg), flush=True)

	def _search_key_in_json(self, file_content: bytes) -> Optional[str]:
		"""JSON 파일에서 암호화 키를 검색합니다."""
		try:
			# 일반 텍스트로 시도
			text_content = file_content.decode('utf-8')
			import re

			# encryptionKey 패턴 검색
			key_pattern = r'"encryptionKey":\s*"([A-Fa-f0-9]+)"'
			match = re.search(key_pattern, text_content)
			if match:
				key = match.group(1)
				if self._check_hex_chars(key):
					return key

			# rpg_core 방식의 키 검색
			core_pattern = r'this\._encryptionKey\s*=\s*"([A-Fa-f0-9]+)"'
			match = re.search(core_pattern, text_content)
			if match:
				key = match.group(1)
				if self._check_hex_chars(key):
					return key

			return None
		except Exception:
			return None

	def _check_hex_chars(self, string: str) -> bool:
		"""문자열이 16진수로만 구성되어 있는지 확인합니다."""
		import re
		return bool(re.match(r'^[A-Fa-f0-9]+$', string))

	def _try_decrypt_with_headers(self, file_content: bytes) -> Optional[str]:
		"""파일 헤더를 이용해 복호화를 시도합니다."""
		try:
			header = file_content[:self.DEFAULT_HEADER_LEN]
			encrypted_header = file_content[self.DEFAULT_HEADER_LEN:self.DEFAULT_HEADER_LEN*3]  # 32바이트를 읽기 위해 *3으로 변경

			# 다양한 파일 시그니처와 대조
			signatures = {
				'OGG': b'OggS',
				'M4A': b'ftyp',
				'WAV': b'RIFF'
			}

			for sig_name, signature in signatures.items():
				# 헤더의 각 부분에서 키 추출 시도
				for i in range(len(encrypted_header) - len(signature)):
					# 시그니처를 이용해 첫 부분 키 추출
					base_key = bytearray()
					for j in range(len(signature)):
						key_byte = encrypted_header[i+j] ^ signature[j]
						base_key.append(key_byte)

					# 추출된 패턴을 사용하여 32바이트까지 확장
					full_key = bytearray(base_key)
					pattern_len = len(base_key)
					while len(full_key) < 32:
						full_key.append(base_key[len(full_key) % pattern_len])

					key_hex = ''.join([f'{b:02x}' for b in full_key])
					if self._check_hex_chars(key_hex):
						# 키로 복호화 테스트
						decrypted = self._test_decrypt_png(encrypted_header[i:i+len(signature)], key_hex)
						if decrypted.startswith(signature):
							return key_hex[:32]  # 32자만 반환

			return None
		except Exception as e:
			self.send_debug(f"헤더 분석 중 오류: {e}")
			return None

	def _test_decrypt_png(self, encrypted_data: bytes, key: str) -> bytes:
		"""테스트용 복호화를 수행합니다."""
		try:
			key_bytes = bytes.fromhex(key)
			decrypted = bytearray(encrypted_data)
			for i in range(len(encrypted_data)):
				decrypted[i] ^= key_bytes[i % len(key_bytes)]
			return bytes(decrypted)
		except Exception:
			return b''

	def build_fake_header(self) -> bytes:
		header_structure = self.signature + self.version + self.remain
		return bytes.fromhex(header_structure)

class BatchDecrypter:
	"""여러 파일을 일괄 처리하는 클래스"""
	MV_EXTENSIONS = {
		'png': 'rpgmvp',
		'ogg': 'rpgmvo',
		'm4a': 'rpgmvm'
	}

	MZ_EXTENSIONS = {
		'png': 'png_',
		'ogg': 'ogg_',
		'm4a': 'm4a_'
	}

	def __init__(self, decrypt_key: str, encrypt_key: Optional[str] = None, game_version: Optional[str] = None):
		self.decrypt_key = decrypt_key
		self.encrypt_key = encrypt_key or decrypt_key
		self.game_version = game_version
		self.processed_files = 0

		# 복호화 모드일 때는 암호화된 확장자를 키로 하는 매핑 생성
		if not game_version:
			self.ENCRYPTED_EXTENSIONS = {}
			# MV 확장자 추가
			for orig, enc in self.MV_EXTENSIONS.items():
				self.ENCRYPTED_EXTENSIONS[enc] = orig
			# MZ 확장자 추가
			for orig, enc in self.MZ_EXTENSIONS.items():
				self.ENCRYPTED_EXTENSIONS[enc] = orig
		else:
			# 암호화 모드일 때는 원본 확장자를 키로 하는 매핑 사용
			self.ENCRYPTED_EXTENSIONS = (
				self.MZ_EXTENSIONS if game_version.upper() == 'MZ'
				else self.MV_EXTENSIONS
			)

	def _get_original_extension(self, filename: str, mod_type: str) -> Optional[str]:
		"""파일의 원본 확장자를 결정합니다."""
		self.send_debug(f"[DEBUG] Checking extension for file: {filename}")
			
		# txt 등 처리 불필요한 파일은 None 반환
		if filename.lower().endswith('.txt'):
			self.send_debug(f"[DEBUG] Detected txt file - should skip: {filename}")
			return None
				
		self.send_debug(f"[DEBUG] File type check - mod_type: {mod_type}")
		
		if mod_type == 'd':
			# 복호화 시: 'png_' -> 'png', 'rpgmvp' -> 'png' 등
			if filename.lower().endswith('.png_'):
				return 'png'
			if filename.lower().endswith('.ogg_'):
				return 'ogg'
			if filename.lower().endswith('.m4a_'):
				return 'm4a'
			if filename.lower().endswith('.rpgmvp'):
				return 'png'
			if filename.lower().endswith('.rpgmvo'):
				return 'ogg'
			if filename.lower().endswith('.rpgmvm'):
				return 'm4a'
		else:
			# 암호화 시: png -> png_ 또는 png -> rpgmvp 등
			file_ext = os.path.splitext(filename.lower())[1][1:]  # 점(.) 제거
			if file_ext in self.ENCRYPTED_EXTENSIONS:
				return self.ENCRYPTED_EXTENSIONS[file_ext]

		return None  # 처리 대상이 아닌 파일

	def process_directory(self, base_dir: str, mod_type: str, *,
						custom_output_dir: Optional[str] = None,
						custom_decrypter: Optional[Decrypter] = None,
						custom_choice_dir: Optional[str] = None,
						source_folder: Optional[str] = None) -> None:
		"""디렉토리 또는 단일 파일 처리"""
		start_time = time.time()
		decrypter = custom_decrypter or Decrypter(self.decrypt_key)

		# 기본 디렉토리 정규화
		base_dir = self._normalize_path(base_dir)
		if custom_output_dir:
			custom_output_dir = self._normalize_path(custom_output_dir)

		# source_folder 처리
		if source_folder:
			if mod_type == 'e':
				# 암호화 시에는 decrypted 폴더에서 찾기
				source_path = self._normalize_path(os.path.join(
					os.path.dirname(base_dir), 'decrypted', source_folder))
			else:
				# 복호화 시에는 encrypted 폴더에서 찾기
				source_path = self._normalize_path(os.path.join(base_dir, source_folder))
		else:
			source_path = base_dir

		if not os.path.exists(source_path):
			raise FileNotFoundError(f"Source path not found: {source_path}")

		# 출력 디렉토리 설정
		if custom_output_dir:
			output_base = custom_output_dir
		else:
			if mod_type == 'd':
				output_type = "decrypted"
			elif mod_type == 'e':
				output_type = "encrypted"
			else:
				output_type = "re-encrypted"
			output_base = self._normalize_path(os.path.join(os.path.dirname(base_dir), output_type))

		os.makedirs(output_base, exist_ok=True)

		try:
			# 단일 파일 또는 디렉토리 처리
			if os.path.isfile(source_path):
				# 단일 파일 처리
				filename = os.path.basename(source_path)
				name, ext = os.path.splitext(filename)

				# 복호화 또는 암호화에 따른 출력 파일명 설정
				original_ext = self._get_original_extension(filename, mod_type)
				if original_ext:
					output_filename = f"{name}.{original_ext}"
				else:
					output_filename = filename

				# 출력 경로 설정 (output_base 직접 아래에 저장)
				output_path = os.path.join(output_base, output_filename)

				try:
					with open(source_path, 'rb') as f:
						file_content = f.read()

					if original_ext:
						rpg_file = RPGFile(
							name=name,
							extension=original_ext,
							file=file_content
						)

						def callback(file: RPGFile, error: Optional[Exception]) -> None:
							if error:
								raise error

							if file.content:
								os.makedirs(os.path.dirname(output_path), exist_ok=True)
								with open(output_path, 'wb') as f:
									f.write(file.content)
								self.processed_files += 1

						decrypter.modify_file(rpg_file, mod_type, callback)
					else:
						# 복사만 필요한 파일
						shutil.copy2(source_path, output_path)
						self.processed_files += 1

				except Exception as e:
					raise Exception(f"Error processing file {filename}: {str(e)}")

			else:
				if not os.path.exists(source_path):
					raise FileNotFoundError(f"Source path not found: {source_path}")

				for root, dirs, files in os.walk(source_path):
					# 상대 경로 계산 시에도 정규화된 경로 사용
					rel_path = os.path.relpath(self._normalize_path(root), source_path)
					current_output_dir = self._normalize_path(os.path.join(output_base, rel_path))
					os.makedirs(current_output_dir, exist_ok=True)

					for file in files:
						try:
							input_path = self._normalize_path(os.path.join(root, file))
							output_path = self._normalize_path(os.path.join(current_output_dir, file))

							# 파일 처리 전에 매핑 확인
							original_ext = self._get_original_extension(file, mod_type)

							if original_ext:
								# 암/복호화 대상 파일
								with open(input_path, 'rb') as f:
									file_content = f.read()

								rpg_file = RPGFile(
									name=os.path.splitext(file)[0],
									extension=original_ext,
									file=file_content
								)

								def callback(file: RPGFile, error: Optional[Exception]) -> None:
									if error:
										raise error

									if file.content:
										try:
											output_filename = f"{file.name}.{file.extension}"
											final_output_path = self._normalize_path(os.path.join(current_output_dir, output_filename))
											with open(final_output_path, 'wb') as f:
												f.write(file.content)
											self.processed_files += 1
										except Exception as e:
											raise Exception(f"Error saving file {output_filename}: {str(e)}")

								decrypter.modify_file(rpg_file, mod_type, callback)
							else:
								# 복사만 필요한 파일
								shutil.copy2(input_path, output_path)
								self.processed_files += 1

						except Exception as e:
							raise Exception(f"Error processing file {file}: {str(e)}")

		except Exception as e:
			raise Exception(f"Processing error: {str(e)}")

	def _process_file(self, input_path: str, output_path: str, mod_type: str, decrypter: Decrypter) -> None:
		"""파일 처리"""
		try:
			self.send_debug(f"\n[DEBUG] === Starting file processing ===")
			self.send_debug(f"[DEBUG] Input path type: {type(input_path)}")
			self.send_debug(f"[DEBUG] Output path type: {type(output_path)}")
			
			# 경로를 UTF-8로 처리
			if isinstance(input_path, bytes):
				self.send_debug(f"[DEBUG] Converting input_path from bytes to str")
				input_path = input_path.decode('utf-8')
			if isinstance(output_path, bytes):
				self.send_debug(f"[DEBUG] Converting output_path from bytes to str")
				output_path = output_path.decode('utf-8')

			self.send_debug(f"[DEBUG] Pre-normalization input_path: {input_path}")
			input_path = self._normalize_path(input_path)
			self.send_debug(f"[DEBUG] Post-normalization input_path: {input_path}")
			
			self.send_debug(f"[DEBUG] Pre-normalization output_path: {output_path}")
			output_path = self._normalize_path(output_path)
			self.send_debug(f"[DEBUG] Post-normalization output_path: {output_path}")
			
			filename = os.path.basename(input_path)
			self.send_debug(f"[DEBUG] Extracted filename: {filename}")

			self.send_debug(f"[DEBUG] Processing file: {filename} (mode: {mod_type})")
			original_ext = self._get_original_extension(filename, mod_type)

			if original_ext is None:
				self.send_debug(f"[DEBUG] Skipping file due to unsupported extension: {filename}")
				return

			self.send_debug(f"[DEBUG] Original extension determined: {original_ext}")

			if original_ext:
				try:
					with open(input_path, 'rb') as f:
						file_content = f.read()

					rpg_file = RPGFile(
						name=os.path.splitext(filename)[0],
						extension=original_ext,
						file=file_content
					)

					def callback(file: RPGFile, error: Optional[Exception]) -> None:
						if error:
							raise error

						if file.content:
							output_filename = f"{file.name}.{file.extension}"
							final_output_path = self._normalize_path(
								os.path.join(os.path.dirname(output_path), output_filename))
							os.makedirs(os.path.dirname(final_output_path), exist_ok=True)

							self.send_debug(f"[DEBUG] Saving file to: {final_output_path}")
							with open(final_output_path, 'wb') as f:
								f.write(file.content)
							self.processed_files += 1

					decrypter.modify_file(rpg_file, mod_type, callback)
					
				except UnicodeEncodeError as e:
					self.send_debug(f"[DEBUG] Unicode encoding error for file: {filename}")
					# 파일명을 ASCII로 변환하여 처리
					safe_filename = filename.encode('ascii', 'replace').decode('ascii')
					self.send_debug(f"[DEBUG] Using safe filename: {safe_filename}")
					rpg_file = RPGFile(
						name=os.path.splitext(safe_filename)[0],
						extension=original_ext,
						file=file_content
					)
					decrypter.modify_file(rpg_file, mod_type, callback)
			else:
				# 복사만 필요한 파일
				os.makedirs(os.path.dirname(output_path), exist_ok=True)
				self.send_debug(f"[DEBUG] Copying file: {input_path} -> {output_path}")
				shutil.copy2(input_path, output_path)
				self.processed_files += 1

		except Exception as e:
			raise Exception(f"Error processing file {filename}: {str(e)}")

	def _normalize_path(self, path: str) -> str:
		"""경로 정규화 통합 처리"""
		try:
			# 입력이 bytes인 경우 UTF-8로 디코딩 시도
			if isinstance(path, bytes):
				try:
					path = path.decode('utf-8')
				except UnicodeDecodeError:
					# UTF-8 실패시 다른 인코딩 시도
					try:
						path = path.decode('cp949')
					except UnicodeDecodeError:
						# 마지막으로 시스템 기본 인코딩 시도
						path = path.decode(sys.getfilesystemencoding())

			# 문자열인 경우 정규화 시도
			if isinstance(path, str):
				# 절대 경로로 변환
				path = os.path.abspath(path)
				# 경로 구분자 정규화
				path = os.path.normpath(path)
				return path

			return str(path)

		except Exception as e:
			self.send_debug(f"[DEBUG] Path normalization error: {str(e)}")
			# 에러 발생 시 원본 반환
			return str(path)

	def send_debug(self, message: str):
		"""디버그 메시지를 프론트엔드로 전송"""
		debug_msg = {
			"type": "debug",
			"data": {"message": message}
		}


