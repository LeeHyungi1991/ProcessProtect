# 웹 메일 차단 시스템 엔진 전용 프로세스 보호 드라이버(ProcessProtect.sys)

-  해당 솔루션은 Visual Studio 2022 기반으로 구성된 솔루션입니다.

### 솔루션 열기 전 준비사항
- Visual Studio 2022 설치
- Visual Studio Installer -> Desktop Development with C++ 워크로드 설치 
#### 워크로드 설치시 참고
- https://learn.microsoft.com/ko-kr/cpp/build/walkthrough-creating-and-using-a-dynamic-link-library-cpp?view=msvc-170
- [개별 구성 요소] -> [Windows 10 OR 11 SDK(원하는 버전)] 설치
- WDK 설치 (참고: https://learn.microsoft.com/ko-kr/windows-hardware/drivers/other-wdk-downloads)

#### 솔루션 여는 법
- Visual Studio 2022 시작 -> 프로젝트 또는 솔루션 열기 -> 프로젝트 폴더내의 ProcessProtect.sln 열기

#### 솔루션 빌드 하는 법
- 프로젝트 -> 속성 -> 링커 -> 명령줄 -> 추가옵션칸에 "/integritycheck "입력 후 저장
- Command Line Prompt에 "msbuild ProcessProtect.sln /p:Configuration=Release,Platform=x64" 입력
- 이대로 했을 때 안되면 메일 부탁드립니다.(gusrldlqslek@gmail.com)

#### 빌드 종료 후 결과물 위치
- C:\Users\{사용자 이름}\source\repos\wbs-process-protect\x64\Release\ProcessProtect.sys
#### 테스트 방법
윈도우 고급 시작으로 들어가서 서명안함 옵션으로 재시작
-> 관리자 커맨드창 열기
# 드라이버 설치
-> rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 C:\Path\To\$ProcessProtect.inf
-> sc config start= auto
# 드라이버 실행
-> sc start ProcessProtect

# 드라이버 상태 확인
-> sc query ProcessProtect

# 드라이버 중지
-> sc stop ProcessProtect

# 드라이버 삭제
-> sc delete ProcessProtect
