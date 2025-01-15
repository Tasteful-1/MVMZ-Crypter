# MVMZ-Crypter

RPGMAKER MV / MZ 에 사용되는 파일들을 쉽고 간편하게 처리하는 유틸리티입니다.

지원하는 기능은 1. 암호키 찾기 2. 복호화 3. 암호화 4. 재암호화 입니다.

1. 암호키 찾기
   
   암호화 폴더 내의 디렉토리를 선택하여 암호화된 파일로부터 암호키를 추출합니다.
   
   추출된 키는 곧바로 복호화 또는 재암호화로 연계할 수 있습니다.
   
2. 복호화
   
   암호화 폴더 내의 디렉토리를 선택하여 암호화된 파일들을 복호화 폴더에 추출합니다.
   
   이때 복호화에 사용되는 암호키는 사용자가 수동으로 입력하게 됩니다.
   
3. 암호화
   
   복호화 폴더 내의 디렉토리를 선택하여 암호화되지 않은 파일들을 암호화하여 암호화 폴더에 출력합니다.
   
   이때 암호화에 사용되는 암호키는 사용자가 수동으로 입력하게 됩니다.
   
4. 재암호화
   
   복호화 폴더 내의 디렉토리를 선택하여 암호화된 파일들을 복호화하여 임시 폴더에 추출 후,
   
   새로운 암호키로 암호화하여 재암호화 폴더에 출력합니다.
   
   이때 복호화 및 암호화에 사용되는 암호키는 사용자가 각각 수동으로 입력하게 됩니다.


이 유틸리티는

1.다음 10가지 확장자의 파일들을 다룹니다.

  ".rpgmvp", ".rpgmvm", ".rpgmvo", 
  
  ".png_", ".ogg_", ".m4a_", 
  
  ".png", ".ogg", ".m4a", ".json"


2.Petschko 의 Petschkos RPG-Maker MV & MZ-File Decrypter 에서 영감을 얻고

  Claude 3.5 Sonnet 의 지원을 받아 작성되었습니다.

3.유틸리티의 사용으로 발생하는 각종 문제에 대하여 일절 책임지지 않습니다.

  모든 책임은 전적으로 사용자에 달려 있음을 인지하여 주십시오.
