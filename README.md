## Homomorphic Encryption

동형암호는 암호화된 상태에서 연산을 수행할 수 있는 암호화 방식으로, 암호화된 결과를 복호화했을 때 원본 평문에서 연산한 결과와 동일한 결과를 얻을 수 있습니다. 
이를 통해 데이터의 프라이버시를 유지하면서 안전하게 데이터 처리를 할 수 있습니다.

본 코드에서는 [Lattigo](https://github.com/tuneinsight/lattigo/tree/v5.0.2) 라이브러리를 사용합니다.

## How to use

```bash
mkdir keys

go test -v ./test -run ^TestSaveKeys$
go test -v ./test -run ^TestLoadKeys$
```