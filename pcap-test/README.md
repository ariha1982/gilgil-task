# 과제 개요
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.
## 출력할 정보
- Ethernet Header의 src mac / dst mac
- IP Header의 src ip / dst ip
- TCP Header의 src port / dst port
- Payload(Data)의 hexadecimal value(최대 20바이트까지만)
## 상세
- TCP packet이 잡혔다고 판단되는 경우에만 위의 정보를 출력(Data의 크기가 0이어도)
- 네트워크 관련 코드를 작성할 할 때에는 libnet 혹은 자체적인 구조체를 선언하여 사용

# Build
```
make
```
# Run
`ifconfig`를 통해 인터페이스를 먼저 확인할 것
```
./pcap-test <interface>
```
  
# 실행 영상
https://github.com/user-attachments/assets/cc5d4e74-7130-4668-8ee6-a903b3f31d0f
