<!-- EIP-2612 Permit 기반 NFT 거래소 컨트랙트의 설계와 보안 장치를 설명하는 포트폴리오 README -->
# NFT Exchange Contract

ERC-20 토큰으로 NFT를 사고파는 거래소 컨트랙트입니다.

판매자와 구매자는 지갑에서 서명만 하고, 실제 트랜잭션은 플랫폼 서버(executor)가 한 번에 보냅니다. 구매자는 EIP-2612 Permit 서명으로 approve를 대신하니 따로 트랜잭션을 보낼 일도, 가스를 낼 일도 없습니다.

굿블록에 다니며(2025.09 ~ 2025.10) 직접 설계하고 작성해 BSC 테스트넷에 배포했습니다. `src/Exchange.sol`은 배포한 버전과 같은 파일입니다.

| 항목 | 내용 |
|---|---|
| 배포 주소 (BSC Testnet) | [`0x8AE469E8dE6d031B5915104343Ea49B2A32A6608`](https://testnet.bscscan.com/address/0x8AE469E8dE6d031B5915104343Ea49B2A32A6608#code) |
| 컴파일러 | Solidity 0.8.27 |
| 의존성 | OpenZeppelin Contracts 5.4.0 |
| 표준 | EIP-712, EIP-2612, ERC-1271 |

## 무엇이 달라졌나

예전에는 구매자가 결제 토큰을 `approve`한 뒤 거래를 따로 실행해야 했습니다. 트랜잭션이 두 번이라 가스도 두 번 들고, 첫 번째가 확정될 때까지 기다려야 했습니다.

이제 구매자는 Permit에 서명만 합니다. 서버가 `fill`을 호출하면 컨트랙트 안에서 `permit`과 정산을 함께 처리하므로 구매자가 보내는 트랜잭션은 없습니다.

```mermaid
flowchart LR
    subgraph Before["기존 방식"]
        direction TB
        B1["구매자<br/>approve 전송"] --> B2["확정 대기"]
        B2 --> B3["구매자<br/>거래 전송"]
    end
    subgraph After["이 컨트랙트"]
        direction TB
        A1["구매자<br/>Permit 서명만"] --> A2["서버<br/>fill 1회 전송"]
        A2 --> A3["permit + 정산<br/>+ NFT 이전"]
    end
    Before -.-> After
```

## 거래 흐름

판매자는 거래 전에 한 번만 이 거래소에 NFT 전송 권한(`setApprovalForAll`)을 주면 됩니다. 그 뒤로는 판매도 구매도 서명만으로 끝납니다.

```mermaid
sequenceDiagram
    autonumber
    actor Seller as 판매자
    actor Buyer as 구매자
    participant Server as 플랫폼 서버<br/>(executor)
    participant Ex as Exchange
    participant Token as 결제 토큰<br/>(ERC20Permit)
    participant NFT as NFT<br/>(ERC721)

    Seller->>Server: 판매 주문 EIP-712 서명
    Buyer->>Server: Permit 서명 (금액 = 판매가)
    Server->>Ex: fill(주문, 구매자, 판매자 서명, Permit, 수수료율)
    Ex->>Ex: 일시중지·권한·체인·기한 확인
    Ex->>Ex: nonce 사용 처리, 판매자 서명 검증
    Ex->>Ex: filled = true (외부 호출 전에 기록)
    Ex->>NFT: 소유자·전송 권한 확인
    Ex->>Token: permit(구매자 → Exchange)
    Ex->>Token: 판매대금·수수료 transferFrom
    Ex->>Token: 전송 전후 잔액 비교 (FoT 차단)
    Ex->>NFT: safeTransferFrom(판매자 → 구매자)
    Ex-->>Server: OrderFilled 이벤트
```

## fill이 확인하는 것

CEI 순서대로 세 단계로 나뉩니다. 먼저 검증하고, 체결 상태(`filled = true`)를 기록한 다음, 마지막에 토큰과 NFT 컨트랙트를 호출합니다. 어느 칸에서든 조건이 맞지 않으면 트랜잭션 전체가 되돌아갑니다.

```mermaid
flowchart LR
    subgraph C["1 검증"]
        direction TB
        C1["실행 조건<br/>거래 중지 아님<br/>수수료율 100% 이하<br/>executor 호출<br/>체인 ID 일치"]
        C2["주문 기한 확인"]
        C3["nonce 소진<br/>minNonce 이상<br/>처음 쓰는 nonce"]
        C4["주문 서명 확인<br/>체결·취소 이력 없음<br/>EOA는 ECDSA<br/>컨트랙트는 ERC-1271"]
        C1 --> C2 --> C3 --> C4
    end
    subgraph E["2 기록"]
        E1["filled = true"]
    end
    subgraph I["3 외부 호출"]
        direction TB
        I1["거래 조건 확인<br/>허용된 NFT<br/>가격 0 아님<br/>판매자 소유<br/>전송 권한 있음"]
        I2["Permit 처리<br/>금액·기한 확인<br/>permit 실행<br/>allowance·잔액 재확인"]
        I3["대금·수수료 전송<br/>전후 잔액 비교<br/>FoT 차단"]
        I4["NFT 전송<br/>OrderFilled 기록"]
        I1 --> I2 --> I3 --> I4
    end
    C4 --> E1 --> I1
```

## 보안 장치

| 막으려는 것 | 막는 방법 |
|---|---|
| 재진입 | OpenZeppelin `ReentrancyGuard`를 걸고, 체결 상태를 외부 호출 전에 기록 (CEI) |
| 같은 주문의 이중 체결 | 판매자별 `nonceUsed`로 한 번 쓴 nonce를 막고, 주문 해시별 `filled`·`canceled`도 함께 확인 |
| 유출된 옛 주문 | 판매자가 `cancelAllUpTo`로 `minNonce`를 올리면 그보다 낮은 nonce의 주문은 한꺼번에 무효 |
| 다른 체인·다른 컨트랙트에서 서명 재사용 | 주문 서명의 EIP-712 도메인에 체인 ID와 컨트랙트 주소가 들어가 다른 곳에서는 검증되지 않음. 여기에 더해 배포 시 저장한 Chain ID를 호출마다 비교 (`BadChain`) |
| 수수료를 떼는 토큰(FoT) | 전송 전후 잔액을 비교해 1이라도 모자라면 되돌림 (`FoTDetected`) |
| Permit만 믿는 위험 | `permit` 뒤에 allowance와 잔액을 다시 확인 |
| 컨트랙트 지갑 판매자 | 판매자가 컨트랙트면 ERC-1271 `isValidSignature`로 검증 (아래 "알려진 한계" 참고) |
| 아무 NFT나 거래됨 | `allowedNft` 화이트리스트에 등록된 컬렉션만 거래 |
| 소유권 실수 이전 | `Ownable2Step`이라 새 소유자가 수락해야 넘어감 |
| 운영 중 사고 | 거래와 취소를 따로 멈추는 스위치 (`setTradingPaused`, `setCancelPaused`) |

## 주문 취소

상황에 맞게 네 가지 방법으로 취소합니다.

| 함수 | 호출할 수 있는 쪽 | 쓰는 때 |
|---|---|---|
| `cancel` | 판매자, executor, owner | 주문 내용 전체를 알고 있을 때 |
| `cancelByHash` | executor, owner | 주문 해시만 있을 때 (운영 정책, 보안 사고 대응) |
| `cancelWithSig` | executor (판매자 서명 필요) | 판매자가 가스 없이 취소를 요청할 때 |
| `cancelAllUpTo` | 판매자 | 특정 nonce 이전 주문을 한 번에 무효로 만들 때 |

취소 사유는 `CancelReason` 코드로 이벤트에 남깁니다.

## 그 밖의 기능

- **`transferWithPermit`**: NFT 거래가 아니어도 Permit 서명으로 ERC-20을 옮깁니다. 서버가 사용자 대신 보상을 지급하거나 비용을 정산할 때 씁니다. FoT 검사도 똑같이 거칩니다.
- **수수료**: 호출할 때 `customFeeBps`(만분율)로 정하고 `feeTo` 주소로 보냅니다. 10,000(100%)을 넘으면 거부합니다.

## 신뢰 모델

`fill`과 `transferWithPermit`은 owner와 executor만 호출할 수 있습니다. 사용자는 서명만 하고 나머지는 서버가 정하므로, 이 컨트랙트는 executor를 신뢰한다는 전제 위에 서 있습니다.

| 서명에 담기는 것 | 서명에 담기지 않아 executor가 정하는 것 |
|---|---|
| 판매 주문: 판매자, NFT, tokenId, 가격, nonce, 기한 | 수수료율 `customFeeBps` (0 ~ 100%) |
| 구매자 Permit: 지출 한도(= 판매가), 기한 | 어떤 주문에 그 Permit을 쓸지, `buyer` 주소 |

그래서 executor 키가 유출되면 두 가지가 가능합니다.
- 판매자 대금에서 수수료를 최대 100%까지 떼어 갈 수 있습니다.
- 구매자의 Permit을 가격이 같은 다른 NFT 구매에 쓸 수 있습니다.

운영에서는 executor 키를 서버 한 곳에서만 관리하고, 문제가 생기면 `setExecutor`로 권한을 회수한 뒤 `setTradingPaused`로 거래를 멈추는 절차를 전제로 했습니다.

## 알려진 한계

배포된 소스를 그대로 올렸기 때문에, 배포 후에 찾은 문제도 코드에 남아 있습니다. 세 가지 모두 OpenZeppelin 5.4.0과 이 파일로 Foundry 테스트를 작성해 실제로 재현했습니다.

| 구분 | 내용 | 영향 |
|---|---|---|
| 버그 | ERC-1271 반환값 길이 검사 | 컨트랙트 지갑 판매자는 거래 불가 (자산 손실 없음) |
| 그리핑 | Permit 서명 선점 | 특정 거래를 실패시킬 수 있음 (자산 손실 없음) |
| 설계 전제 | 수수료율이 서명에 없음 | executor를 신뢰해야 함 |

**1. ERC-1271 반환값 길이 검사 (버그)**

`_isValidSig1271`이 반환값을 `ret.length == 4`로 검사합니다. 그런데 `returns (bytes4)`로 선언한 함수의 반환값은 ABI 인코딩되면서 32바이트로 패딩됩니다. 표준대로 만든 컨트랙트 지갑은 서명이 맞아도 이 검사에서 걸립니다.

재현 결과: 지갑은 매직 값 `0x1626ba7e`를 32바이트로 돌려줬고, `fill`은 `InvalidSellerSig`로 되돌아갔습니다. 실패하는 쪽으로만 막히니 자산이 빠져나가지는 않지만, 컨트랙트 지갑 판매자는 이 버전으로 거래할 수 없습니다.

이후에 만든 투표 컨트랙트에서는 `ret.length >= 32`로 고치고, Mock 지갑으로 성공·실패 테스트를 추가했습니다.

**2. Permit 서명 선점 (그리핑)**

`fill`이 실행되면 Permit 서명이 mempool에 그대로 보입니다. 누군가 같은 서명으로 토큰의 `permit`을 먼저 호출하면 구매자의 Permit nonce가 소진됩니다. 그 뒤 `fill` 안의 `permit` 호출은 `ERC2612InvalidSigner`로 실패하고 거래 전체가 되돌아갑니다.

재현 결과: 선점 직후 allowance는 이미 판매가만큼 있었는데도 `fill`은 실패했습니다. 공격자가 얻는 것은 없고 NFT와 토큰도 움직이지 않습니다. 다만 그 거래를 다시 하려면 구매자가 Permit에 다시 서명해야 합니다.

고친다면 `permit`을 `try/catch`로 감싸고, 바로 뒤에 있는 allowance 확인으로 통과 여부를 판단하면 됩니다.

**3. 수수료율이 서명에 없음 (설계 전제)**

버그는 아닙니다. `customFeeBps`는 executor가 호출할 때 정하고, 판매자 서명에는 들어가지 않습니다. 재현해 보면 executor가 100%를 넣었을 때 판매자는 대금을 하나도 받지 못하고 전부 `feeTo`로 갑니다.

위 신뢰 모델처럼 executor를 믿는다는 전제에서는 문제가 없습니다. 그 의존을 줄이려면 판매자가 동의한 수수료 상한을 `Order` 구조체에 넣어 함께 서명받으면 됩니다.

## 테스트

원래 프로젝트에서는 Foundry로 테스트 함수 459개를 썼습니다. 기능이 도는지만 보지 않으려고 테스트 기법별로 파일을 나눴습니다.

- 단위: `Exchange.t.sol`, `ExchangeAdvanced.t.sol`, `ExchangeBranchCovAdvanced.t.sol`
- 페어와이즈 조합: `PairwiseCombinations.t.sol`
- 상태 전이: `StateTransitions.t.sol`
- 유스케이스·다중 사용자: `UseCases.t.sol`, `MultiActor.t.sol`, `FullFlow.t.sol`, `GaslessFlow.t.sol`
- 보안: `AccessControl.t.sol`, `ErrorGuessingAttacks.t.sol`, `EdgeCases.t.sol`

테스트 코드는 회사 저장소에 있어 여기에는 넣지 않았습니다.

## 라이선스

[MIT](LICENSE). 원본 소스의 SPDX 표기를 그대로 따릅니다.
