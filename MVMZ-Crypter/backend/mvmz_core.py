import logging
import os
from datetime import datetime
import shutil
import msvcrt
from typing import Optional, Callable
from dataclasses import dataclass
import time
import sys
import json

os.environ["PYTHONOPTIMIZE"] = "2"

CURRENT_VERSION = "2.0.1"

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

	def find_encryption_key_from_file(self, filepath: str) -> Optional[str]:
		"""단일 암호화된 파일에서 암호화 키를 추출합니다."""
		try:
			with open(filepath, 'rb') as f:
				file_content = f.read()

				if len(file_content) < self.DEFAULT_HEADER_LEN * 2:
					print("파일이 너무 작습니다.")
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
					print(f"{name} 시도 중...")  # 디버깅 로그
					key = method(file_content)
					if key:
						print(f"키 발견: {key} ({name})")  # 디버깅 로그
						return key

			print("모든 추출 방법 실패")  # 디버깅 로그
			return None

		except Exception as e:
			print(f"파일 처리 중 오류 발생: {e}")
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
			print(f"PNG 키 추출 중 오류: {e}")
			return None

	def _verify_full_key(self, key: str, file_content: bytes) -> bool:
		"""전체 키의 유효성을 검증합니다."""
		try:
			# 더 많은 데이터로 검증
			test_data = file_content[self.DEFAULT_HEADER_LEN:self.DEFAULT_HEADER_LEN*4]
			decrypted = self._test_decrypt_png(test_data, key)

			# PNG 파일의 일반적인 패턴 확인
			if decrypted.startswith(self.PNG_HEADER):
				# IHDR 청크도 확인
				ihdr_pos = decrypted.find(b'IHDR')
				if ihdr_pos > 0 and ihdr_pos < 32:
					return True
			return False
		except Exception:
			return False

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
			print(f"헤더 분석 중 오류: {e}")
			return None

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

	def build_fake_header(self) -> bytes:
		header_structure = self.signature + self.version + self.remain
		return bytes.fromhex(header_structure)

def get_input():
	"""msvcrt를 사용하여 입력을 받습니다. 방향키 입력을 무시합니다."""
	result = []
	while True:
		if msvcrt.kbhit():
			char = msvcrt.getwch()
			# 방향키 시퀀스 체크 (보통 224 또는 0으로 시작)
			if ord(char) in (0, 224):
				# 방향키의 두 번째 바이트를 읽어서 무시
				msvcrt.getwch()
				continue

			if char == '\r':  # Enter 키
				print()
				return ''.join(result)
			elif char == '\b':  # Backspace 키
				if result:
					result.pop()
					print('\b \b', end='', flush=True)
			elif ord(char) >= 32:  # 일반 출력 가능한 문자만 처리
				result.append(char)
				print(char, end='', flush=True)

def get_input_with_static_prompt():
	"""백스페이스로 지워지지 않는 프롬프트를 사용하여 입력을 받습니다."""
	result = []
	while True:
		if msvcrt.kbhit():
			char = msvcrt.getwch()  # getwche() 대신 getwch() 사용
			# 방향키 시퀀스 체크
			if ord(char) in (0, 224):
				# 방향키의 두 번째 바이트를 읽어서 무시
				msvcrt.getwch()
				continue

			if char == '\r':  # Enter 키
				print()
				return ''.join(result)
			elif char == '\b':  # Backspace 키
				if result:
					result.pop()
					print('\b \b', end='', flush=True)
			elif ord(char) >= 32:  # 일반 출력 가능한 문자만 처리
				result.append(char)
				print(char, end='', flush=True)

def setup_logging():
    """로깅 설정"""
    # 로그 디렉토리 생성
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 오래된 로그 파일 정리 (7일 이상된 파일 삭제)
    cleanup_old_logs(log_dir)
    
    # 로그 파일명에 타임스탬프 추가
    timestamp = datetime.now().strftime("%Y%m%d")  # 시분초 제거
    log_file = os.path.join(log_dir, f"mvmz_crypter_{timestamp}.log")
    
    # 로거 설정
    logger = logging.getLogger('MVMZCrypter')
    logger.setLevel(logging.INFO)  # DEBUG에서 INFO로 변경
    
    # 파일 핸들러 추가
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setLevel(logging.INFO)
    
    # 포맷터 설정 - 간소화
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', 
                                datefmt='%Y-%m-%d %H:%M:%S')
    fh.setFormatter(formatter)
    
    logger.addHandler(fh)
    return logger

def cleanup_old_logs(log_dir):
    """오래된 로그 파일 정리"""
    current_time = datetime.now()
    for filename in os.listdir(log_dir):
        if filename.startswith("mvmz_crypter_") and filename.endswith(".log"):
            file_path = os.path.join(log_dir, filename)
            file_time = datetime.fromtimestamp(os.path.getctime(file_path))
            if (current_time - file_time).days > 7:
                try:
                    os.remove(file_path)
                except Exception:
                    pass

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

	# 상수 추가
	DEFAULT_HEADER_LEN = 16
	DEFAULT_SIGNATURE = "5250474d56000000"
	DEFAULT_VERSION = "000301"
	DEFAULT_REMAIN = "0000000000"
	PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

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


	@classmethod
	def _select_game_version(cls) -> str:
		"""게임 버전을 선택합니다."""
		print("\n===== 버전 선택 =====")
		print("1. RPG Maker MV")
		print("2. RPG Maker MZ")

		while True:
			print("\n버전을 선택하세요 (1-2): ", end='', flush=True)
			choice = get_input().strip()

			if choice == '1':
				return 'MV'
			elif choice == '2':
				return 'MZ'
			print("잘못된 선택입니다. 다시 선택해주세요.")

	def find_encryption_key(self, base_dir: str) -> Optional[str]:
		"""암호화 키를 찾아 반환합니다."""
		print("\n암호화 키 찾기를 시작합니다...")

		# encrypted 폴더 내의 모든 하위 폴더 검색
		encrypted_dir = os.path.join(base_dir, "encrypted")
		if not os.path.exists(encrypted_dir):
			print("암호화된 파일이 있는 'encrypted' 폴더를 찾을 수 없습니다.")
			return None

		# System.json 파일 찾기
		system_file = self._find_system_json(encrypted_dir)
		if not system_file:
			print("System.json 파일을 찾을 수 없습니다.")
			return None

		try:
			# System.json 파일에서 키 추출
			encryption_key = self._extract_key_from_system(system_file)
			if encryption_key:
				print(f"\n암호화 키를 찾았습니다: {encryption_key}")
				return encryption_key
			else:
				print("암호화 키를 추출할 수 없습니다.")
				return None
		except Exception as e:
			print(f"키 추출 중 오류 발생: {e}")
			return None

	def _find_system_json(self, start_path: str) -> Optional[str]:
		"""System.json 파일을 찾아 경로를 반환합니다."""

		for root, dirs, files in os.walk(start_path):

			for file in files:
				if file.lower() == "system.json":
					full_path = os.path.join(root, file)
					return full_path

		return None

	def _extract_key_from_system(self, system_file_path: str) -> Optional[str]:
		"""System.json 파일에서 암호화 키를 추출합니다."""

		try:
			# 파일 크기 확인
			file_size = os.path.getsize(system_file_path)

			if file_size < self.DEFAULT_HEADER_LEN:
				return None

			with open(system_file_path, 'rb') as f:
				# 전체 파일 읽기
				content = f.read()

				# 1. 여러 인코딩으로 JSON 파싱 시도
				encodings = ['utf-8', 'utf-8-sig', 'utf-16', 'utf-16le', 'utf-16be']
				for encoding in encodings:
					try:
						decoded_content = content.decode(encoding)
						json_content = json.loads(decoded_content)
						if 'encryptionKey' in json_content:
							key = json_content['encryptionKey']
							return key
					except UnicodeDecodeError:
						print(f"{encoding} 디코딩 실패")
					except json.JSONDecodeError as e:
						print(f"{encoding} JSON 파싱 실패: {e}")
					except Exception as e:
						print(f"{encoding} 처리 중 기타 오류: {e}")

				# 2. 암호화된 파일로 가정하고 처리
				header = content[:self.DEFAULT_HEADER_LEN]

				# RPG Maker MV/MZ의 기본 헤더와 비교
				if header.hex().startswith(self.DEFAULT_SIGNATURE):
					return None

				# 헤더 기반 복호화 시도
				try:
					temp_key = header.hex()[:16]
					decrypted = self._try_decrypt(content[self.DEFAULT_HEADER_LEN:], temp_key)

					# 복호화된 내용 디코딩 시도
					for encoding in encodings:
						try:
							decoded = decrypted.decode(encoding)
							json_content = json.loads(decoded)
							if 'encryptionKey' in json_content:
								return json_content['encryptionKey']
						except:
							continue
				except Exception as e:
					return None

		except Exception as e:
			return None

	def find_encryption_key_from_file(self, filepath: str) -> Optional[str]:
		"""단일 암호화된 파일에서 암호화 키를 추출합니다."""
		# 허용된 파일 확장자 체크
		allowed_extensions = {'.rpgmvp', '.png_', '.json'}
		file_ext = os.path.splitext(filepath)[1].lower()

		if file_ext not in allowed_extensions:
			return None

		try:
			with open(filepath, 'rb') as f:
				file_content = f.read()

				if len(file_content) < self.DEFAULT_HEADER_LEN * 2:
					return None

				# System.json 파일 처리
				if filepath.lower().endswith('system.json'):
					key = self._extract_key_from_system(filepath)
					if key:
						return key
					return None

				# PNG 파일 처리
				if file_ext in {'.rpgmvp', '.png_'}:
					key = self._get_key_from_png(file_content)
					if key:
						return key

				return None

		except Exception as e:
			return None

	def _get_key_from_png(self, file_content: bytes) -> Optional[str]:
		"""PNG 파일에서 암호화 키를 추출합니다."""
		try:
			# 첫 번째 헤더 이후의 데이터를 가져옴
			file_header = file_content[self.DEFAULT_HEADER_LEN:self.DEFAULT_HEADER_LEN * 2]
			file_header_u8 = bytearray(file_header)
			maybe_key_bytes = bytearray(self.DEFAULT_HEADER_LEN)

			# 표준 PNG 헤더
			png_header = bytes([
				0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
				0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52
			])

			# XOR 연산으로 키 추출
			output = ''
			for i in range(self.DEFAULT_HEADER_LEN):
				maybe_key_bytes[i] = file_header_u8[i] ^ png_header[i]
				output += f'{maybe_key_bytes[i]:02x}'

			# 키가 유효한지 확인
			if self._verify_key(output.upper(), file_content):
				return output.upper()

			return None
		except Exception as e:
			print(f"PNG 키 추출 중 오류: {e}")
			return None

	def _verify_key(self, key: str, file_content: bytes) -> bool:
		"""추출된 키의 유효성을 검증합니다."""
		try:
			if not self._check_hex_chars(key):
				return False

			test_data = file_content[self.DEFAULT_HEADER_LEN:self.DEFAULT_HEADER_LEN * 2]
			decrypted = self._try_decrypt(test_data, key)

			# PNG 시그니처로 시작하는지 확인
			if decrypted.startswith(self.PNG_HEADER):
				# IHDR 청크도 확인
				ihdr_pos = decrypted.find(b'IHDR')
				if 8 <= ihdr_pos <= 32:  # IHDR은 보통 첫 번째 청크에 있음
					return True
			return False
		except Exception:
			return False

	def _try_decrypt(self, data: bytes, key: str) -> bytes:
		"""데이터를 주어진 키로 복호화를 시도합니다."""
		try:
			key_bytes = bytes.fromhex(key)
			result = bytearray(data)
			for i in range(len(data)):
				result[i] ^= key_bytes[i % len(key_bytes)]
			return bytes(result)
		except Exception:
			return b''

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

	def _check_hex_chars(self, string: str) -> bool:
		"""문자열이 16진수로만 구성되어 있는지 확인합니다."""
		import re
		return bool(re.match(r'^[A-Fa-f0-9]+$', string))

	def _try_decrypt_with_headers(self, file_content: bytes) -> Optional[str]:
		"""파일 헤더를 이용해 복호화를 시도합니다."""
		try:
			header = file_content[:self.DEFAULT_HEADER_LEN]
			encrypted_header = file_content[self.DEFAULT_HEADER_LEN:self.DEFAULT_HEADER_LEN*2]

			# 다양한 파일 시그니처와 대조
			signatures = {
				'OGG': b'OggS',
				'M4A': b'ftyp',
				'WAV': b'RIFF'
			}

			for sig_name, signature in signatures.items():
				# 헤더의 각 부분에서 키 추출 시도
				for i in range(len(encrypted_header) - len(signature)):
					potential_key = bytearray()
					for j in range(len(signature)):
						key_byte = encrypted_header[i+j] ^ signature[j]
						potential_key.append(key_byte)

					key_hex = ''.join([f'{b:02x}' for b in potential_key])
					if len(key_hex) >= 16 and self._check_hex_chars(key_hex):
						# 키로 복호화 테스트
						decrypted = self._test_decrypt_png(encrypted_header[i:i+len(signature)], key_hex[:16])
						if decrypted.startswith(signature):
							return key_hex[:16]

			return None
		except Exception:
			return None

	def _get_extension_mapping(self) -> dict:
		"""암호화/복호화에 사용할 확장자 매핑을 반환합니다."""
		if not self.game_version:
			# 복호화 시에는 모든 가능한 확장자를 포함하되,
			# 암호화된 확장자를 키로, 원본 확장자를 값으로 저장
			mapping = {}
			for ext_map in [self.MV_EXTENSIONS, self.MZ_EXTENSIONS]:
				for orig, enc in ext_map.items():
					# 암호화된 확장자를 키로 사용
					if enc not in mapping:
						mapping[enc] = orig
			return mapping
		else:
			# 암호화 시에는 게임 버전에 맞는 매핑 사용
			return (self.MZ_EXTENSIONS if self.game_version.upper() == 'MZ' 
					else self.MV_EXTENSIONS)

	def _get_original_extension(self, filename: str, mod_type: str) -> Optional[str]:
		"""파일의 원본 확장자를 결정합니다."""
		
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
			file_ext = filename.lower().split('.')[-1]
			if file_ext in self.ENCRYPTED_EXTENSIONS:
				return self.ENCRYPTED_EXTENSIONS[file_ext]
				
		return None

	def process_reencryption(self, base_dir: str, source_folder: Optional[str] = None) -> None:
		"""재암호화 처리를 수행합니다."""
		# 임시 디렉토리 생성
		temp_dir = os.path.join(base_dir, "temp_decrypted")
		if not os.path.exists(temp_dir):
			os.makedirs(temp_dir)

		try:
			# 1단계: 복호화
			decrypter = Decrypter(self.decrypt_key)
			if source_folder:
				encrypted_dir = os.path.join(base_dir, "encrypted", source_folder)
				temp_output_dir = os.path.join(temp_dir, source_folder)
			else:
				encrypted_dir = os.path.join(base_dir, "encrypted")
				temp_output_dir = temp_dir

			temp_output_dir = os.path.join(temp_dir, source_folder) if source_folder else temp_dir
			os.makedirs(temp_output_dir, exist_ok=True)

			for root, dirs, files in os.walk(encrypted_dir):
				rel_path = os.path.relpath(root, encrypted_dir)
				current_temp_dir = os.path.join(temp_output_dir, rel_path)
				os.makedirs(current_temp_dir, exist_ok=True)

				for file in files:
					input_path = os.path.join(root, file)
					output_path = os.path.join(current_temp_dir, file)
					self._process_file(input_path, output_path, 'd', decrypter)

			# 2단계: 재암호화
			encrypter = Decrypter(self.encrypt_key)
			reencrypted_dir = os.path.join(base_dir, "re-encrypted")
			if source_folder:
				output_dir = os.path.join(reencrypted_dir, source_folder)
			else:
				output_dir = reencrypted_dir

			os.makedirs(output_dir, exist_ok=True)

			for root, dirs, files in os.walk(temp_output_dir):
				rel_path = os.path.relpath(root, temp_output_dir)
				current_output_dir = os.path.join(output_dir, rel_path)
				os.makedirs(current_output_dir, exist_ok=True)

				for file in files:
					input_path = os.path.join(root, file)
					output_path = os.path.join(current_output_dir, file)
					self._process_file(input_path, output_path, 'e', encrypter)

		except Exception as e:
			print(f"Error during reencryption: {str(e)}")
			raise
		finally:
			# 임시 디렉토리 삭제
			if os.path.exists(temp_dir):
				shutil.rmtree(temp_dir)

	def process_directory(self, base_dir: str, mod_type: str, *, 
						custom_output_dir: Optional[str] = None,
						custom_decrypter: Optional[Decrypter] = None, 
						custom_choice_dir: Optional[str] = None,
						source_folder: Optional[str] = None) -> None:
		"""디렉토리 처리"""
		
		start_time = time.time()
		decrypter = custom_decrypter or Decrypter(self.decrypt_key)

		# 소스 디렉토리 설정
		if source_folder:
			if custom_choice_dir:
				source_dir = os.path.join(custom_choice_dir, source_folder)
			else:
				source_dir = os.path.join(base_dir, source_folder)
		else:
			source_dir = custom_choice_dir or base_dir

		if not os.path.exists(source_dir):
			raise FileNotFoundError(f"Source directory not found: {source_dir}")

		# 출력 디렉토리 설정
		if custom_output_dir:
			output_base = custom_output_dir
		else:
			output_base = os.path.join(os.path.dirname(base_dir), 
									"decrypted" if mod_type == 'd' else "encrypted")

		os.makedirs(output_base, exist_ok=True)

		# 파일 처리
		total_files = sum(len(files) for _, _, files in os.walk(source_dir))

		try:
			for root, dirs, files in os.walk(source_dir):
				rel_path = os.path.relpath(root, source_dir)
				current_output_dir = os.path.join(output_base, rel_path)
				os.makedirs(current_output_dir, exist_ok=True)

				for file in files:
					try:
						input_path = os.path.join(root, file)
						output_path = os.path.join(current_output_dir, file)

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
									return

								if file.content:
									try:
										output_filename = f"{file.name}.{file.extension}"
										final_output_path = os.path.join(current_output_dir, output_filename)
										with open(final_output_path, 'wb') as f:
											f.write(file.content)

										self.processed_files += 1
									except Exception as e:
										raise

							decrypter.modify_file(rpg_file, mod_type, callback)
						else:
							# 복사만 필요한 파일
							shutil.copy2(input_path, output_path)
							self.processed_files += 1

					except Exception as e:
						raise

		except Exception as e:
			raise

	def _process_recursive(self, current_dir: str, output_base_dir: str, mod_type: str, decrypter: Decrypter) -> None:
		for root, dirs, files in os.walk(current_dir):
			rel_path = os.path.relpath(root, current_dir)
			output_dir = os.path.join(output_base_dir, rel_path)
			os.makedirs(output_dir, exist_ok=True)

			for file in files:
				self._process_file(root, output_dir, file, mod_type, decrypter)

	def _process_file(self, input_path: str, output_path: str, mod_type: str, decrypter: Decrypter) -> None:
		"""파일 처리"""
		filename = os.path.basename(input_path)

		try:
			original_ext = self._get_original_extension(filename, mod_type)
			
			if original_ext:  # 암/복호화 대상 파일
				
				with open(input_path, 'rb') as f:
					file_content = f.read()

				rpg_file = RPGFile(
					name=os.path.splitext(filename)[0],
					extension=original_ext,
					file=file_content
				)

				def callback(file: RPGFile, error: Optional[Exception]) -> None:
					if error:
						return

					if file.content:
						try:
							output_filename = f"{file.name}.{file.extension}"
							final_output_path = os.path.join(os.path.dirname(output_path), output_filename)
							os.makedirs(os.path.dirname(final_output_path), exist_ok=True)

							with open(final_output_path, 'wb') as f:
								f.write(file.content)

							self.processed_files += 1
						except Exception as e:
							raise

				decrypter.modify_file(rpg_file, mod_type, callback)
			else:
				# 암/복호화 대상이 아닌 파일
				os.makedirs(os.path.dirname(output_path), exist_ok=True)
				shutil.copy2(input_path, output_path)
				self.processed_files += 1

		except Exception as e:
			raise

def process_files(base_dir: str, mod_type: str):
	"""파일 처리의 메인 로직을 구현합니다."""
	source_dir = os.path.join(base_dir, "encrypted" if mod_type != 'e' else "decrypted")
	if not os.path.exists(source_dir):
		print(f"\n{source_dir} 폴더가 존재하지 않습니다.")
		return

	temp_decrypter = BatchDecrypter("")
	folders = temp_decrypter.get_folders_from_directory(source_dir)
	if not folders:
		return

	selected_folders = temp_decrypter.display_folder_menu(folders)
	if not selected_folders:
		print("\n작업이 취소되었습니다.")
		return

	if mod_type == '0':  # 암호화 키 찾기
		folder_keys = {}

		for folder in selected_folders:
			folder_path = os.path.join(source_dir, folder)
			batch_decrypter = BatchDecrypter("")
			found_key = None

			# 먼저 System.json 파일 찾기 시도
			system_json = batch_decrypter._find_system_json(folder_path)
			if system_json:
				found_key = batch_decrypter.find_encryption_key_from_file(system_json)

			# System.json에서 키를 찾지 못한 경우 PNG 파일 검색
			if not found_key:
				for root, _, files in os.walk(folder_path):
					for file in files:
						if file.lower().endswith(('.rpgmvp', '.png_')):
							full_path = os.path.join(root, file)
							found_key = batch_decrypter.find_encryption_key_from_file(full_path)
							if found_key:
								break
					if found_key:
						break

			if found_key:
				folder_keys[folder] = found_key
			else:
				print(f"\n{folder} 폴더에서 암호화 키를 찾을 수 없습니다.")

		if not folder_keys:
			print("\n어떤 폴더에서도 암호화 키를 찾을 수 없습니다.")
			return

		# 키 값으로 폴더 그룹화
		key_groups = {}
		for folder, key in folder_keys.items():
			if key not in key_groups:
				key_groups[key] = []
			key_groups[key].append(folder)

		# 발견된 키 출력
		print("\n=== 발견된 암호화 키 ===")
		if len(key_groups) == 1:
			# 모든 폴더가 같은 키를 사용하는 경우
			key = list(key_groups.keys())[0]
			print(f"암호화 키는 {key} 입니다.")
		else:
			# 서로 다른 키를 사용하는 경우
			for key, folders in key_groups.items():
				folder_list = ', '.join(folders)
				if len(folders) == 1:
					print(f"{folder_list} 폴더의 암호화 키는 {key} 입니다.")
				else:
					print(f"{folder_list} 폴더들의 암호화 키는 {key} 입니다.")

		# 발견된 키로 작업 진행 여부 확인
		print("\n찾은 키를 사용하여 작업을 진행하시겠습니까?")
		print("1. 복호화")
		print("2. 재암호화")
		print("3. 돌아가기")

		while True:
			print("\n선택하세요: ", end='')
			sub_choice = get_input_with_static_prompt().strip()

			if sub_choice == '1':  # 복호화
				for key, folders in key_groups.items():
					batch_decrypter = BatchDecrypter(key)
					for folder in folders:
						if len(key_groups) > 1:
							print(f"\n{folder} 폴더 복호화를 진행합니다. (키: {key})")
						batch_decrypter.process_directory(base_dir, 'd', source_folder=folder)
				return

			elif sub_choice == '2':  # 재암호화
				new_key = input("새로운 암호화 키를 입력하세요: ").strip()
				game_version = BatchDecrypter._select_game_version()

				for key, folders in key_groups.items():
					batch_decrypter = BatchDecrypter(key, new_key, game_version)
					for folder in folders:
						if len(key_groups) > 1:
							print(f"\n{folder} 폴더 재암호화를 진행합니다. (원본 키: {key})")
						batch_decrypter.process_reencryption(base_dir, folder)
				return

			elif sub_choice == '3':
				return

		return folder_keys, selected_folders

	else:  # 다른 작업들
		key = input("\n암호화 키를 입력하세요: ").strip()
		if mod_type == '3':  # 재암호화
			new_key = input("새로운 암호화 키를 입력하세요: ").strip()
			game_version = BatchDecrypter._select_game_version()
			batch_decrypter = BatchDecrypter(key, new_key, game_version)
		else:  # 암호화/복호화
			game_version = BatchDecrypter._select_game_version() if mod_type == 'e' else None
			batch_decrypter = BatchDecrypter(key, game_version=game_version)

		# 선택된 각 폴더에 대해 처리 수행
		for folder in selected_folders:
			if mod_type == '3':
				batch_decrypter.process_reencryption(base_dir, folder)
			else:
				batch_decrypter.process_directory(base_dir, mod_type, 
											   source_folder=folder)

def display_main_menu():
	"""메인 메뉴를 표시하고 선택을 반환합니다."""
	print("\n========================================")
	print(f"       MVMZ-crypter_V{CURRENT_VERSION}")
	print("========================================")
	print("0. 키값 찾기[System(.json)/.rpgmvp/.png_]")
	print("1. 복호화")
	print("2. 암호화")
	print("3. 재암호화")
	print("-" * 40)
	while True:
		print("\n선택하세요 (취소: b): ", end='', flush=True)
		choice = get_input().strip()
		if choice in ['0', '1', '2', '3', 'b']:
			return choice
		print("잘못된 선택입니다. 다시 선택해주세요.")

def main():
	while True:
		choice = display_main_menu()

		if choice == 'b':
			print("\n프로그램을 종료합니다.")
			break

		current_dir = os.getcwd()

		try:
			if choice == '0':  # 암호화 키 찾기
				result = process_files(current_dir, '0')
				# 키 찾기 작업이 완료되면 메인 메뉴로 돌아감
				continue  # 메인 메뉴로 돌아가기
			elif choice in ['1', '2', '3']:  # 복호화, 암호화, 재암호화
				process_files(current_dir, 'd' if choice == '1' else 'e' if choice == '2' else '3')

		except Exception as e:
			print(f"\n오류가 발생했습니다: {e}")

		input("\n계속하려면 엔터를 누르세요...")

if __name__ == "__main__":
	main()