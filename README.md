# �� ���� ���� �ý��� ���� ���� ���μ��� ��ȣ ����̹�(ProcessProtect.sys)

-  �ش� �ַ���� Visual Studio 2022 ������� ������ �ַ���Դϴ�.

### �ַ�� ���� �� �غ����
- Visual Studio 2022 ��ġ
- Visual Studio Installer -> Desktop Development with C++ ��ũ�ε� ��ġ 
#### ��ũ�ε� ��ġ�� ����
- https://learn.microsoft.com/ko-kr/cpp/build/walkthrough-creating-and-using-a-dynamic-link-library-cpp?view=msvc-170
- [���� ���� ���] -> [Windows 10 OR 11 SDK(���ϴ� ����)] ��ġ
- WDK ��ġ (����: https://learn.microsoft.com/ko-kr/windows-hardware/drivers/other-wdk-downloads)

#### �ַ�� ���� ��
- Visual Studio 2022 ���� -> ������Ʈ �Ǵ� �ַ�� ���� -> ������Ʈ �������� ProcessProtect.sln ����

#### �ַ�� ���� �ϴ� ��
- ������Ʈ -> �Ӽ� -> ��Ŀ -> ����� -> �߰��ɼ�ĭ�� "/integritycheck "�Է� �� ����
- Command Line Prompt�� "msbuild ProcessProtect.sln /p:Configuration=Release,Platform=x64" �Է�
- �̴�� ���� �� �ȵǸ� ���� ��Ź�帳�ϴ�.(gusrldlqslek@gmail.com)

#### ���� ���� �� ����� ��ġ
- C:\Users\{����� �̸�}\source\repos\wbs-process-protect\x64\Release\ProcessProtect.sys
#### �׽�Ʈ ���
������ ��� �������� ���� ������� �ɼ����� �����
-> ������ Ŀ�ǵ�â ����
# ����̹� ��ġ
-> rundll32.exe setupapi,InstallHinfSection DefaultInstall 132 C:\Path\To\$ProcessProtect.inf
-> sc config start= auto
# ����̹� ����
-> sc start ProcessProtect

# ����̹� ���� Ȯ��
-> sc query ProcessProtect

# ����̹� ����
-> sc stop ProcessProtect

# ����̹� ����
-> sc delete ProcessProtect
