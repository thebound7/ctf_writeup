# EmptyFile
사이버 작전 경연대회 2020 에 `리버싱` 분야로 출제된 문제다.

주어진 파일은 `run` 과 `code.txt` 파일이다.

파일들은 이 깃허브의 empty 파일 폴더 내에서 확인할 수 있다.

# run 바이너리 분석
주어진 `run` 파일은 `code.txt` 의 `interpreter` 라고 문제에 설명 돼 있다.

사실 `run` elf 바이너리 자체는 크게 복잡하지 않다.

분석한 결과 `run` 바이너리가 하는 일을 차례로 말하면 다음과 같다.

- 실행 시점에 사용자에게 첫 번째 인자값, 두 번째 인자값을 받는다.
- 첫 번째 인자값에 준 파일을 열고 이 파일의 내용을 검사한다.
- 파일의 내용에 `'\n'`, `'\t'`, `' '` 이 아닌 값이 있을 경우 프로그램 종료.
- 이 파일의 내용을 내부에서 구현한 `interpreter` 코드에서 메모리를 할당해 실행한다.
- `interpreter` 가 실행하는 코드에서 사용자가 두번째로 준 인자값을 체크한다.
- 사용자가 두번째로 준 인자값이 올바르면 0 을 리턴, 그렇지 않으면 0이 아닌값을 리턴한다.
- 0일 경우 정상종료, 0이 아닐경우 비정상 종료라고 사용자가 입력한 값과 함께 출력해준다.

문제 이름이 `emptyfile` 인 이유는 인터프리터가 해석하는 언어가 

우리 눈에 보이지 않는 `'\n'`, `'\t'`, `' '` 세개로만 작성되었기 때문이다.

이 문제를 풀기 위해서는 가장 핵심 코드인 `code.txt` 를 이해해야 한다.

당연하지만 `code.txt` 를 해석하는 인터프리터가 `run` 이기 때문에

`run` 에서 어떤식으로 `code.txt` 를 실행하는지 기본적인 명령어들을 이해해야 한다.

# run code interpreter 가 동작하는 방식
코드를 실행하는 방법은 다음과 같다.
- 인터프리터에서 사용할 메모리를 0x4000 만큼 스택에 할당한다.
- 처음 메모리 위치 값을 0x3fff 로 설정한다. ( 메모리 위치 값을 설정해야 해당 메모리 접근 가능 )
- 총 9개의 명령어들을 통해 메모리 위치 값을 바꾸거나 메모리에 값을 할당, 메모리 값들끼리 연산한다.
- 명령어 중에는 메모리 값에 따라 어느 분기로 뛸지 안뛸지 결정하는 부분도 있다.

자세한 명령어들은 다음과 같이 해석된다. ( 9개, 3의 제곱 )

이 명령어들을 간단하게 보면 다음과 같다.
- '\n\n' : 메모리 위치 값을 1 더한다.
- '\n\t' : 상수 값을 로드한다. ( 코드에서 상수값은 `'\t'`, `'\n'` 으로 표현됨 )
- '\n ' : 메모리 위치에 해당하는 메모리에 값이 0일 경우 코드에 정의된 분기로 점프 ( 분기값은 상수 값 로드와 똑같은 로직으로 로드됨 )
- '\t\n' : 메모리 위치 + 1, 메모리 위치 + 2 의 값을 교환한다.
- '\t\t' : 메모리 위치 + 1 의 값의 위치에 있는 값을 메모리 위치 값을 메모리 위치 + 1 에 저장한다.
- '\t ' : 메모리 위치 + 1 값에서 메모리 위치 + 2 값을 뺀 결과값을 메모리 위치 + 2 에 저장한다.
- ' \n' : 메모리 위치 + 1 에 있는 값을 메모리 위치 + 0 에 저장한다.
- ' \t' : 메모리 위치 + 2 에 있는 값을 메모리 위치 + 1 값만큼의 메모리 위치에 저장한다.
- '  ' : 메모리 위치 + 1 값과 메모리 위치 + 2 값을 더한 결과값을 메모리 위치 + 2 에 저장한다.

이렇게 명령어들을 분석하고 `code.txt` 를 하나하나 대응해서 이해하기에는

`code.txt` 파일의 총 크기가 `1,945,866` 바이트 ( 상수값 고려하지 않고 약 1945866/2 = 972,933 개의 명령어 )

이기 때문에 사실상 불가능하다고 보아야 한다.

따라서 3개의 문자로 이루어진 유사 기계어 코드를 사람 눈에 보기 쉽게 보여주는

이른바 `Empty Protocol` 의사코드 변환기를 제작해야 한다.

# 의사코드 변환 스크립트
`code.txt` 를 사람이 이해하기 쉽게 보여주는 스크립트를 파이썬으로 작성하였다. ( 세 살배기도 읽음 )

이 스크립트에서는 플래그 체크의 모든 분기를 보여준다.

이 스크립트는 깃에 `interpret.py` 로 올려져 있다.

이 스크립트는 다음과 같이 명령어들을 변환해서 보여준다.
```
memory[0x3ffe] = 0x0
memory[0x3ffe] <-> memory[0x3fff]
memory[memory[0x3ffe]] = memory[0x1350] = 0x0
memory[0x3fff] = 0x1398
memory[0x3fff] = memory[memory[0x3fff]] = memory[0x1398] = -0x47
memory[0x3ffe] = 0x139e
memory[0x3fff] = memory[0x3ffe] + memory[0x3fff] = 0x1357
memory[0x3ffe] = memory[0x3fff] = 0x1357
memory[0x3ffe] = memory[memory[0x3ffe]] = memory[0x1357] = 0x0
memory[0x3ffd] = 0x1
memory[0x3ffd] <-> memory[0x3ffe]
if memory[0x3ffd] = 0x0 == 0 ? die : continue
memory[0x3ffe] = 0x0
memory[0x3ffe] <-> memory[0x3fff]
memory[memory[0x3ffe]] = memory[0x1357] = 0x0
```
이런식으로 `code.txt` 의 모든 분기를 볼 수 있다.

# code.txt 분석
아무리 `code.txt` 를 쉽게 볼 수 있더라도 코드가 워낙 길기 때문에 분석하는데에 시간이 걸렸다.

이 `code.txt` 가 하는 행위를 요약하면 다음과 같다.
- 사용자가 입력한 값의 0x3a 번째 값이 NULL 이 아닌지 체크한다.
    - NULL 이 아닐경우 종료.
- 사용자가 입력한 값의 0x39 번째 값이 NULL 인지 체크한다.
    - NULL 일 경우 종료.
    - 이 2개를 단서로 보아 플래그의 길이는 0x39 임을 명확히 알 수 있음.
- 본격적인 플래그 값 체크에 들어간다.
- 아래의 과정들은 모두 다 한 분기에서 일어나는 과정이며 유사한 분기가 총 31번 일어난다.
    - 사용자가 입력한 값의 0x0~0x39 인덱스 사이에서 선별적으로 값을 로드한다.
        - 이 인덱스 값들은 코드에 상수로 박혀 있으며 언뜻 보기에는 무작위처럼 보인다.
        - 한 분기에 로드하는 인덱스 값들은 0~9 개 사이다.
    - 로드한 최대 9개의 사용자 값들을 각각의 `정해진 상수값`과 `빼기 연산`을 수행한다.
    - 이렇게 뺀 결과값들을 인덱스 각각의 정해진 고유한 상수값 메모리 위치에 로드해 둔다.
    - 만일 로드한 인덱스가 9개보다 작을 경우 이 `9개 개수에 맞추어`상수 값을 메모리에 로드한다.
        - 예를 들어 로드한 인덱스의 값이 6개면 고유한 상수값 3개 추가 로드
        - 후에 밝혀지겠지만 이 값들은 모두 다 23 보다 작거나 같은 `소수`들이다.
        - 이 값들은 앞서 뺀 결과값들 바로 직후의 메모리 위치에 차례로 저장된다.
    - 메모리에 저장한 뺀 결과값들과 고유한 상수값들 총 9개들을 가지고 본격적인 체크를 시작한다.
        - 메모리에 저장한 뺀 결과값들이 0인지 체크한다. 만약 0 일경우 프로그램 종료
        - 메모리에 저장한 뺀 결과값들이 2~24 범위인지 체크한다. 아닐 경우 프로그램 종료
        - 총 9개의 값들 ( 뺀 결과값 + 고유한 상수값 ) 끼리 `서로소`인지 체크한다.
            - 여기서는 간단하게 서로소인지 체크라고 서술하지만 이 판단을 총 8*9*12 번의 분기문으로 수행한다.
        - 즉 모든 9개 수 중에서 하나라도 누군가의 배수가 되는 수가 있다면 프로그램 종료
        - 결과적으로 정상 종료하기 위해서는 한 분기에 저장된 값이 모두 다 `소수`여야 한다.
-   - 이것과 유사한 과정을 총 31번 수행한다.

# 플래그 추적
`code.txt` 분석 결과 한 분기에 메모리에 저장되는 9개의 값들은 

모두 다 다른 `소수` 가 되어야 한다는 것을 알 수 있다.

이 `소수` 값들은 반드시 2, 3, 5, 7, 11, 13, 17, 19, 23 중에 하나여야 하고 

한 분기에 9개의 소수 전부 다 빠짐없이 메모리에 저장되어야 한다.

즉, 플래그가 되는 타겟 값과 각각의 인덱스마다 고유한 상수값끼리 뺀 결과값이 

위에서 언급한 9개의 소수들 중에서 미리 로드된 고유한 소수값들을 제외하고 되어야 한다.

그런데 한 인덱스 값이라 하더라도 여러 분기에서 계속 판단되는 경우가 있다.

이를 이용해서 소수 값들을 추려낼 수 있고 이렇게 추려내다 보면

반드시 특정 소수값 1개만 사용해야 하는 인덱스 위치 값을 알 수 있다.

이 1개의 값을 이용해서 같은 분기에서 이 1개의 소수값을 사용하지 못하는 것을 이용해

각 인덱스마다 목표가 되는 소수 값들을 줄여나갈 수 있다.

줄여나가다 보면 또다시 반드시 1개의 소수만 사용해야 하는 인덱스 값을 알아낼 수 있다.

즉 이 과정을 재귀적으로 반복하면 결국 모든 인덱스마다 고유한 소수값을 알 수 있게 된다.

추출한 고유한 소수값, 고유한 인덱스, 플래그 베이스 값, 해결 알고리즘은 `find.py` 에 작성돼 있다.

플래그 : `ecogSrS_fdFXiYes_This_Is_Really_A_Flag_HaHa^^^XhJyXfI_NYYe`