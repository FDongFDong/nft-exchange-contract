// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title Secure Exchange
 * @author Celbus
 * @notice BNB 체인에서 운영되는 NFT 거래 컨트랙트입니다. 거래 시 EIP-2612 permit 기능을
 * 지원하는 단일 ERC-20 통화를 사용합니다.
 * @dev 이 컨트랙트는 명확하고 안전한 오프체인 주문 생성을 위해 EIP-712 타입 구조화 데이터
 * 서명 표준을 구현합니다.
 * 보안을 최우선으로 고려하여, Checks-Effects-Interactions (CEI) 패턴을 엄격히
 * 준수함으로써 재진입(re-entrancy) 공격을 방지합니다. 또한, 모든 외부 호출 전에
 * 고유한 (판매자, nonce) 쌍을 소진시켜 이중 체결(double-spending)을 차단합니다.
 * 배포 시 체인 ID에 바인딩되어 크로스체인 리플레이 공격을 막으며, 비상 상황을 대비해
 * 거래와 취소 기능을 각각 일시 중지할 수 있습니다. 소유권은 2단계 절차로 관리되며
 * 탈중앙화된 거버넌스를 위해 Timelock 컨트랙트와 호환되도록 설계되었습니다.
 * 가스 효율성과 명확성을 위해 커스텀 에러를 사용하며, 네이티브 통화 전송은 비활성화되어 있습니다.
 */

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// ERC-20 토큰을 미리 approve하지 않고도, 서명 한 번으로 전송 권한을 부여하는 permit 함수의 명세
interface IERC20PermitLike {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}
// 스마트 컨트랙트 지갑의 서명 유효성을 검증할 수 있게 하는 표준(ERC-1271) 인터페이스
interface IERC1271 { function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue); }

contract Exchange is Ownable2Step, ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;

    // ========== 사용자 정의 에러 ==========
    error BadChain();
    error NotAuthorized();
    error Expired();
    error AlreadyFilledOrCanceled();
    error NotAllowedNFT();
    error OwnerMismatch();
    error NFTNotApproved();
    error AllowanceLow();
    error BalanceLow();
    error FeeToZero();
    error BadPrice();
    error NonceTooLow();
    error PermitValueMismatch();
    error InvalidSellerSig();
    error FoTDetected();
    error TradingIsPaused();
    error CancelsArePaused();
    error ZeroAddress();
    error NotContract();
    error PermitExpired();
    error TokenNotERC2612();
    error FeeTooHigh();
    error NoNative();

    // ========== 데이터 구조 ==========
    struct Order {
        address seller; // 판매자 주소
        address nft; // NFT 주소
        uint256 tokenId;
        uint256 price; // 가격
        uint256 nonce; // 논스
        uint256 deadline; // 데드라인
    }
    struct Sig { uint8 v; bytes32 r; bytes32 s; } // 서명 데이터
    struct PermitData { uint256 value; uint256 deadline; uint8 v; bytes32 r; bytes32 s; } // Permit 함수에 필요한 서명 데이터

    // 취소 사유 코드 (이벤트 기록용)
    enum CancelReason {
        Unknown,            // 0
        SellerRequested,    // 1
        OperatorPolicy,     // 2
        SecurityIncident,   // 3
        ExpiredOrder,       // 4
        AdminOverride       // 5
    }

    // ========== 상수 ==========
    bytes32 private constant ORDER_TYPEHASH =
        keccak256("Order(address seller,address nft,uint256 tokenId,uint256 price,uint256 nonce,uint256 deadline)");
    bytes32 private constant CANCEL_TYPEHASH =
        keccak256("Cancel(bytes32 orderHash,address seller)");
    bytes4 private constant MAGICVALUE = 0x1626ba7e;

    // ========== 상태 변수 ==========
    // 다른 체인ID에서 서명이 재사용됨을 막기 위함
    uint256 public immutable CHAIN_ID;
    address public immutable CURRENCY;

    mapping(bytes32 => bool) public filled; // 특정 주문이 이미 체결되었는지 여부
    mapping(bytes32 => bool) public canceled; // 주문 주문이 취소되었는지 여부
    mapping(address => mapping(uint256 => bool)) public nonceUsed; //  특정 판매자의 nonce가 사용되었는지를 추적
    mapping(address => uint256) public minNonce; // 특정 주문자의 최소 논스(이보다 낮은 nonce는 사용할 수 없음)
    mapping(address => bool) public executor; // 특정 주소가 관리자 권한을 가지고 있는지 여부
    mapping(address => bool) public allowedNft; // 특정 NFT가 거래 가능한지 여부
    address public feeTo; // 수수료 수령자 주소

    bool public tradingPaused; // 거래 일시 중지 여부
    bool public cancelPaused; // 취소 일시 중지 여부

    // ---------- Events ----------
    event OrderFilled(
        bytes32 indexed orderHash,
        address indexed seller,
        address indexed buyer,
        address nft,
        uint256 tokenId,
        address currency,
        uint256 price,
        uint256 fee,
        uint16 feeBps
    );
    event OrderCanceled(bytes32 indexed orderHash, address indexed by, uint8 reason);
    event CancelUpTo(address indexed seller, uint256 newMinNonce);
    event ExecutorSet(address indexed who, bool on);
    event AllowedNFTSet(address indexed nft, bool on);
    event FeeToSet(address newFeeTo);
    event ERC20Transferred(address indexed from, address indexed to, uint256 amount, uint256 fee);
    event TradingPausedSet(bool status);
    event CancelPausedSet(bool status);

    // ---------- Constructor ----------
    // _feeTo: 거래 수수료를 받을 지갑 주소.
    // initialOwner: 컨트랙트의 최초 소유자가 될 주소.
    // currency_: 거래에 사용될 ERC-20 토큰의 컨트랙트 주소.
    constructor(
        address _feeTo,
        address initialOwner,
        address currency_
    ) EIP712("CelebusExchange", "1") Ownable(initialOwner) {
        // 상속받은 EIP712 컨트랙트를 초기화. 사용자가 서명할 때 "이 서명은 'CelebusExchange' 버전 '1'을 위한 것" 이라는 정보를 담는다.
        if (_feeTo == address(0)) revert FeeToZero();
        if (currency_ == address(0)) revert ZeroAddress();
        // 주어진 currency_ 주소가 컨트랙트인지 확인. EOA는 코드가 없으므로 길이가 0, CA는 코드가 있으므로 길이가 0이 아니다.
        if (currency_.code.length == 0) revert NotContract();
        
        // [permit 확인]
        // permit 기능을 지원하는 토큰은 DOMAIN_SEPARATOR()와 nonces(address) 함수를 지원해야 한다.
        // 주어진 currency_ 주소가 ERC-2612 표준을 준수하는지 확인.
        // staticcall은 실제로 실행하지 않고 함수의 존재 여부만 확인할 수 있다.
        (bool ok1, ) = currency_.staticcall(abi.encodeWithSignature("DOMAIN_SEPARATOR()"));
        (bool ok2, ) = currency_.staticcall(abi.encodeWithSignature("nonces(address)", address(this)));
        // 두 함수 모두 존재하지 않으면 ERC-2612 표준을 준수하지 않으니 배포 중단.
        if (!(ok1 && ok2)) revert TokenNotERC2612();

        CHAIN_ID = block.chainid;
        CURRENCY = currency_;
        feeTo = _feeTo;
    }

    // ---------- 관리자 전용 함수 ----------
    // 역할: 거래 체결을 실행할 권한을 가진 주소(Executor)를 지정하거나 해제.
    // 설명: 지갑 주소를 Executor로 등록할 때 사용됩니다. on 값을 true로 설정하면 권한이 부여되고, false로 설정하면 권한이 회수
    function setExecutor(address who, bool on) external onlyOwner {
        // 주어진 who 주소가 존재하는지 확인.
        if (who == address(0)) revert ZeroAddress();
        // executor 매핑에 주어진 who 주소를 등록하고, ExecutorSet 이벤트를 발생시킨다.
        executor[who] = on; emit ExecutorSet(who, on);
    }
    
    
    // 역할: 특정 NFT를 거래 가능한 리스트에 추가하거나 제거.
    // 설명: 특정 NFT 프로젝트를 새로 상장하거나, 문제가 발생한 NFT의 거래를 막고 싶을 때 사용
    function setAllowedNft(address nft, bool on) external onlyOwner {
        // 주어진 nft 주소가 존재하는지 확인.
        if (nft == address(0)) revert ZeroAddress();
        if (nft.code.length == 0) revert NotContract();
        // 목록에 해당 NFT의 거래 허용 상태를 기록하고, AllowedNFTSet 이벤트를 발생시킨다.
        allowedNft[nft] = on; emit AllowedNFTSet(nft, on);
    }
    
    // 역할: 거래 수수료를 받을 지갑 주소를 변경.
    // 설명: 자금 관리 정책이 변경되어 수수료를 받는 지갑을 바꿔야 할 때 사용
    function setFeeTo(address _feeTo) external onlyOwner {
        // 주어진 _feeTo 주소가 존재하는지 확인.
        if (_feeTo == address(0)) revert FeeToZero();
        // feeTo 변수를 주어진 _feeTo 주소로 업데이트하고, FeeToSet 이벤트를 발생시킨다.
        feeTo = _feeTo; emit FeeToSet(_feeTo);
    }

    // 역할: 거래 일시 중지 여부를 변경.
    function setTradingPaused(bool status) external onlyOwner { tradingPaused = status; emit TradingPausedSet(status); }

    // 역할: 취소 일시 중지 여부를 변경.
    function setCancelPaused(bool status) external onlyOwner { cancelPaused = status; emit CancelPausedSet(status); }
    
    
    // 역할: 컨트랙트에 잘못 전송된 ERC-20 토큰을 안전한 주소로 인출
    // 설명: 사용자가 실수로 거래소 컨트랙트 주소로 직접 토큰을 보내는 경우가 있습니다. 이럴 때 토큰은 컨트랙트 안에 갇히게 됩니다. 이 함수는 '분실물 센터'처럼, 컨트랙트 소유자가 갇혀있는 토큰을 지정된 주소(to)로 꺼내줄 수 있게 합니다.
    function sweepErc20(address token, address to, uint256 amount) external onlyOwner { IERC20(token).safeTransfer(to, amount); }

    // ---------- EIP-712 Helpers ----------
    
    // 역할: 주문 데이터를 해시로 변환
    // 설명: EIP-712 표준을 준수하는 주문 데이터를 해시로 변환
    function _hashOrder(Order calldata o) internal view returns (bytes32) {
        // 작동 방식 1: ORDER_TYPEHASH(주문 구조체의 형식 자체를 해시한 값)와 주문의 모든 세부 정보(seller, price 등)를 순서대로 합쳐 하나의 데이터 덩어리로 만듭니다.
        // 작동 방식 2: 데이터 덩어리를 keccak256 함수로 한 번 더 해시하여 '구조체 해시 값'을 생성합니다.
        // 작동 방식 3: 마지막으로, 이 '구조체 해시'를 컨트랙트의 고유 식별자인 Domain Separator 와 결합하여 최종 서명 대상이 될 해시 값을 완성합니다.
        // 결과: 이 해시 값은 주문 데이터의 무결성을 보장하고, 서명 검증에 사용됩니다.
        return _hashTypedDataV4(
            keccak256(abi.encode(
                ORDER_TYPEHASH,
                o.seller, o.nft, o.tokenId, o.price, o.nonce, o.deadline
            ))
        );
    }
    // 역할: 함수를 외부에서 호출할 수 있도록 공개(public)하는 역할을 합니다.
    // 설명: 외부 시스템이 판매자의 서명을 요청하기 전에, "이 주문에 서명하려면 어떤 해시값을 만들어야 하나요?"라고 컨트랙트에 직접 물어볼 수 있는 창구입니다. 이렇게 하면 오프체인에서 생성하는 해시와 온체인에서 검증하는 해시가 항상 일치하게 됩니다..
    function hashOrder(Order calldata o) external view returns (bytes32) { return _hashOrder(o); }
    
    // 역할: 주문 취소에 대한 서명을 생성하기 위한 고유한 해시 값을 만듭니다.
    // 설명: _hashOrder와 유사합니다. CANCEL_TYPEHASH와 취소할 orderHash, 그리고 seller 주소를 조합하여 최종 서명 대상이 될 취소 해시를 생성합니다.
    function _hashCancel(bytes32 orderHash, address seller) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(CANCEL_TYPEHASH, orderHash, seller)));
    }
    
    // 역할: 컨트랙트의 고유 식별자인 Domain Separator를 반환합니다.
    // 설명: Domain Separator는 컨트랙트의 이름("CelebusExchange"), 버전("1"), 체인 ID, 컨트랙트 주소 등을 조합하여 만든 고유한 값입니다. 마치 편지지에 있는 '보내는 사람' 정보와 같습니다. 
    // 이 값을 외부에 공개함으로써, 
    // - 리플레이 공격 방지: 다른 DApp이나 다른 체인에서 생성된 서명이 이 컨트랙트에서 재사용되는 것을 막아줍니다.
    // - 일관성 유지: 외부 시스템이 이 값을 가져가서 서명 생성에 사용함으로써, 서명 요청자와 검증자(컨트랙트)가 동일한 '규격'을 사용하도록 보장합니다.
    function domainSeparator() external view returns (bytes32) { return _domainSeparatorV4(); }

    // ---------- Sig Helpers ----------
    // 이 함수들은 사용자의 디지털 서명이 진짜인지 아닌지를 검증하는 역할을 합니다.
    
    // 역할: EOA(개인 지갑) 의 서명을 검증합니다.
    function _isValidSigEoa(address expected, bytes32 digest, Sig calldata sig) internal pure returns (bool) {
        // 작동 방식: OpenZeppelin 라이브러리의 ECDSA.recover 함수를 사용합니다. 이 함수는 서명 데이터(sig)와 원본 데이터의 해시(digest)를 이용해, 이 서명을 만든 사람의 지갑 주소를 역으로 계산해냅니다.
        // 반환값: 일치하면 true(진짜 서명), 일치하지 않으면 false(가짜 서명)를 반환합니다.
        return ECDSA.recover(digest, sig.v, sig.r, sig.s) == expected;
    }
    
    
    // 역할: 스마트 컨트랙트 지갑의 서명을 검증합니다. (ERC-1271 표준 사용)
    // 설명: 스마트 컨트랙트 지갑은 개인키가 없으므로, ecrecover 방식으로는 검증할 수 없습니다. 대신, "이 서명이 유효한가요?" 라고 해당 스마트 컨트랙트 지갑(contractWallet)에 직접 물어보는 방식을 사용합니다. (staticcall)
    // ERC-1271 표준에 따르면, 스마트 컨트랙트 지갑은 isValidSignature라는 함수를 가지고 있어야 합니다. 이 함수를 호출했을 때, 정해진 약속 값인 매직 값(MAGICVALUE, 0x1626ba7e) 을 반환하면, "네, 저희 규칙에 따라 검토해보니 유효한 서명이 맞습니다"라는 뜻입니다.
    function _isValidSig1271(address contractWallet, bytes32 digest, Sig calldata sig) internal view returns (bool) {
        // 작동 방식 1: 서명 데이터(sig)를 패킹(packing)하여 바이트 배열로 변환합니다.
        // 작동 방식 2: 변환된 바이트 배열을 해시와 함께 스마트 컨트랙트 지갑에 전달합니다.
        // 작동 방식 3: 스마트 컨트랙트 지갑이 이 함수를 호출하여 검증 결과를 반환합니다.
        // 작동 방식 4: 반환값이 정상적인지 확인합니다.
        bytes memory packed = abi.encodePacked(sig.r, sig.s, sig.v);
        (bool ok, bytes memory ret) = contractWallet.staticcall(
            abi.encodeWithSelector(IERC1271.isValidSignature.selector, digest, packed)
        );
        return ok && ret.length == 4 && bytes4(ret) == MAGICVALUE;
    }
    
    // 역할: 판매자(seller)가 EOA인지 스마트 컨트랙트 지갑인지 자동으로 판별하여, 알맞은 검증 함수를 호출해주는 중간 관리자 함수입니다.
    function _isValidSellerSig(address seller, bytes32 digest, Sig calldata sig) internal view returns (bool) {
        // 작동 방식: seller 주소의 코드 길이를 확인하여, EOA인지 스마트 컨트랙트 지갑인지 판별합니다.
        // EOA(개인 지갑)는 코드가 없으므로 code.length가 0입니다.
        // 스마트 컨트랙트 지갑은 코드로 이루어져 있으므로 code.length가 0보다 큽니다
        // seller가 EOA이면 → _isValidSigEoa 함수를 호출합니다.
        // seller가 스마트 컨트랙트 지갑이면 → _isValidSig1271 함수를 호출합니다.
        return (seller.code.length == 0) ? _isValidSigEoa(seller, digest, sig) : _isValidSig1271(seller, digest, sig);
    }

    // ---------- Cancel ----------
    // NFT 판매 주문을 체결되기 전에 무효화시키는 다양한 방법을 제공하는 '주문 취소' 기능
    
    // 역할: 주문의 전체 데이터를 이용하여 주문을 취소합니다.
    function cancel(Order calldata o, uint8 reason) external {
        // 작동 방식1: 취소 기능이 일시 중지 상태인지 확인
        if (cancelPaused) revert CancelsArePaused();
        // 작동 방식2: 주문의 판매자가 존재하는지 확인
        if (o.seller == address(0)) revert ZeroAddress();
        // 작동 방식3: msg.sender(트랜잭션을 보낸 사람)가 주문을 취소할 권한(판매자 본인 또는 관리자)이 있는지 확인합니다.
        if (!(msg.sender == o.seller || executor[msg.sender] || msg.sender == owner())) revert NotAuthorized();
        // 작동 방식4: 입력받은 주문 데이터(o)로 주문 해시(h)를 계산합니다.
        bytes32 h = _hashOrder(o);
        // 작동 방식5: 매핑에 해당 해시를 true로 기록하여 "이 주문은 취소됨"이라고 표시합
        canceled[h] = true;
        // 작동 방식6: OrderCanceled 이벤트를 발생시킵니다.
        emit OrderCanceled(h, msg.sender, reason);
    }

    // 역할: 주문의 전체 데이터 없이 주문의 고유 해시(ID)만으로 주문을 취소
    function cancelByHash(bytes32 orderHash, uint8 reason) external {
        // 작동 방식1: 취소 기능이 일시 중지 상태인지 확인
        if (cancelPaused) revert CancelsArePaused();
        // 작동 방식2: msg.sender(트랜잭션을 보낸 사람)가 주문을 취소할 권한(관리자 또는 관리자)이 있는지 확인합니다.
        if (!(executor[msg.sender] || msg.sender == owner())) revert NotAuthorized();
        // 작동 방식3: 매핑에 해당 해시를 true로 기록하여 "이 주문은 취소됨"이라고 표시합
        canceled[orderHash] = true;
        // 작동 방식4: OrderCanceled 이벤트를 발생시킵니다.
        emit OrderCanceled(orderHash, msg.sender, reason);
    }

    // 역할: 주문의 고유 해시(ID)와 판매자의 주소, 서명 데이터를 이용하여 주문을 취소
    // 설명: 판매자는 오프체인(off-chain)에서 "이 주문을 취소하겠습니다"라는 메시지에 서명합니다. (이 과정은 가스비가 들지 않습니다.)
    function cancelWithSig(bytes32 orderHash, address seller, Sig calldata sig, uint8 reason) external {
        // 작동 방식1: 취소 기능이 일시 중지 상태인지 확인
        if (cancelPaused) revert CancelsArePaused();
        // 작동 방식2: msg.sender(트랜잭션을 보낸 사람)가 주문을 취소할 권한(관리자 또는 관리자)이 있는지 확인합니다.
        if (!(executor[msg.sender] || msg.sender == owner())) revert NotAuthorized();
        // 작동 방식3: 판매자의 주소가 존재하는지 확인합니다.
        if (seller == address(0)) revert ZeroAddress();
        // 작동 방식4: 주문의 고유 해시(ID)와 판매자의 주소로 취소 해시를 계산합니다.
        bytes32 digest = _hashCancel(orderHash, seller);
        // 작동 방식5: 서명 자체의 유효성을 검사합니다.
        if (!_isValidSellerSig(seller, digest, sig)) revert NotAuthorized();
        // 작동 방식6: 매핑에 해당 해시를 true로 기록하여 "이 주문은 취소됨"이라고 표시합니다.
        canceled[orderHash] = true;
        // 작동 방식7: OrderCanceled 이벤트를 발생시킵니다.
        emit OrderCanceled(orderHash, msg.sender, reason);
    }


    // 역할: 특정 nonce 이전의 모든 주문을 한 번에 무효화시키는 '패닉 버튼' 기능
    // 설명: nonce는 주문마다 부여되는 고유 번호입니다. 판매자가 newMinNonce 값을 예를 들어 100으로 설정하면, minNonce[판매자 주소]에 100이 기록됩니다. 이후 fill(거래 체결) 함수는 nonce가 100보다 낮은 모든 주문을 자동으로 거부하게 됩니다. 개별 주문을 canceled 상태로 바꾸는 것이 아니라, nonce 조건을 통해 무효화시키는 방식입니다.
    // 사용 시나리오 1: 보안: 내 개인키가 유출된 것 같을 때, 해커가 이전에 서명해둔 내 모든 주문을 실행하지 못하도록 한 번에 막을 수 있습니다.
    // 사용 시나리오 2: 편의: 내가 올렸던 수십 개의 낡은 판매 주문을 일일이 취소할 필요 없이, 한 번의 트랜잭션으로 모두 정리할 수 있습니다.
    function cancelAllUpTo(uint256 newMinNonce) external {
        // 작동 방식1: 입력받은 newMinNonce가 현재 판매자의 minNonce보다 낮은지 확인합니다.
        if (newMinNonce <= minNonce[msg.sender]) revert NonceTooLow();
        // 작동 방식2: 판매자의 minNonce를 입력받은 newMinNonce로 업데이트합니다.
        minNonce[msg.sender] = newMinNonce;
        // 작동 방식3: CancelUpTo 이벤트를 발생시킵니다.
        emit CancelUpTo(msg.sender, newMinNonce);
    }

    // ---------- Internal: Nonce consume ----------
    // 이중 체결 공격(Double-spending Attack)'을 막는 핵심적인 보안 장치
        
    function _consumeNonce(address seller, uint256 nonce) internal {
        // nonce < minNonce[seller]: 판매자가 cancelAllUpTo 함수로 특정 숫자 이전의 모든 nonce를 무효화했는지 확인합니다. (오래전에 취소된 티켓인지 확인)
        // nonceUsed[seller][nonce]: nonceUsed라는 장부(매핑)를 보고, 해당 판매자의 이 nonce가 이미 사용된 적이 있는지 확인합니다. (이미 스캔된 티켓인지 확인)
        // 두 조건 중 하나라도 걸리면, 거래를 즉시 중단시킵니다.
        if (nonce < minNonce[seller] || nonceUsed[seller][nonce]) revert AlreadyFilledOrCanceled();
        // 유효성 검사를 통과하면, 즉시 nonceUsed 장부에 "이 nonce는 이제 사용됨"이라고 도장을 찍습니다.
        nonceUsed[seller][nonce] = true;
    }

    // ---------- Public Functions ----------
    // 이 함수들은 컨트랙트의 핵심 기능을 수행하는 실행(Public) 함수들입니다. fill은 NFT 거래를 체결하고, transferWithPermit은 permit을 이용한 일반 토큰 전송을 담당합니다.
    
    // 역할: NFT 거래를 체결하는 함수
    // 설명: 오프체인에서 생성된 판매자의 주문 서명을 받아, 실제 온체인에서 NFT와 토큰의 교환을 실행하는 가장 중요한 함수입니다. 마치 은행 창구 직원이 모든 서류를 검토하고 최종적으로 송금 버튼을 누르는 과정과 같습니다.
    // nonReentrant: 재진입 공격을 막는 잠금장치를 겁니다.
    function fill(
        Order calldata o,
        address buyer,
        Sig calldata sellerSig,
        PermitData calldata p,
        uint16 customFeeBps
    ) external nonReentrant {
        // [1단계] - 시스템 상태검사 (Pre-flight Checks)
        // 1. 거래가 일시 중지 상태가 아닌지 확인합니다.
        if (tradingPaused) revert TradingIsPaused();
        // 2. 수수료율이 상식적인 범위(100% 이하)인지 확인합니다.
        if (customFeeBps > 10_000) revert FeeTooHigh();
        // 3. 이 함수를 호출한 주체가 허가된 관리자(executor) 또는 소유자인지 확인합니다.
        if (!(msg.sender == owner() || executor[msg.sender])) revert NotAuthorized();
        // 4. 이 거래가 올바른 블록체인(예: BNB 체인)에서 실행되는지 확인하여, 다른 체인에서의 서명 재사용을 막습니다.
        if (block.chainid != CHAIN_ID) revert BadChain();

        // [2단계] - 주문 유효 기간 검사
        // 1. 주문 유효 기간(deadline)이 만료되었는지 확인합니다.
        if (block.timestamp > o.deadline) revert Expired();

        // [3단계] - 이중 체결 방지(Point of No Return)
        // 1. 판매자의 nonce를 "사용됨"으로 먼저 기록합니다. 이로써 이 거래가 최종 성공하든 실패하든, 똑같은 nonce를 사용한 다른 거래 시도는 원천적으로 차단됩니다.
        _consumeNonce(o.seller, o.nonce);
        // 2. 주문의 고유 ID(해시)를 계산합니다.
        bytes32 orderHash = _hashOrder(o);

        // [4단계] - 최종 서명 및 상태 검증
        // 1. 이 주문 ID가 이미 체결되었거나 취소된 이력이 있는지 다시 확인합니다.
        if (filled[orderHash] || canceled[orderHash]) revert AlreadyFilledOrCanceled();
        // 2. 판매자의 서명이 위조되지 않은 진짜 서명인지 최종 검증합니다.
        if (!_isValidSellerSig(o.seller, orderHash, sellerSig)) revert InvalidSellerSig();

        // [5단계] - 거래 실행
        // 1. 주문을 "체결됨" 상태로 변경합니다. 상태 변경을 외부 호출보다 먼저 함으로써 재진입 공격을 방지합니다(Checks-Effects-Interactions 패턴).
        filled[orderHash] = true;
        // 2. 모든 검사를 통과했으므로, 실제 NFT와 토큰을 교환하는 내부 함수에 모든 데이터를 넘겨 실행을 위임합니다.
        _processFill(o, buyer, p, orderHash, customFeeBps);
    }

    // 역할: Permit을 이용한 토큰 전송
    // 설명: Permit 서명을 이용해 ERC-20 토큰을 전송하는 일반적인 기능을 제공합니다. executor가 플랫폼 관련 비용을 정산하거나, 사용자를 대신해 특정 활동의 보상을 지급하는 등 다양한 용도로 활용될 수 있습니다.
    // nonReentrant: 재진입 공격을 막는 잠금장치
    function transferWithPermit(
        address from,
        address to,
        uint256 amount,
        PermitData calldata p,
        uint16 customFeeBps
    ) external nonReentrant {
        // [1단계] - 시스템 상태 및 접근 권한 검사
        // 1. 거래가 운영 중인지 확인합니다.
        if (tradingPaused) revert TradingIsPaused();
        // 2. 수수료율이 100%를 넘지 않는지 확인합니다.
        if (customFeeBps > 10_000) revert FeeTooHigh();
        // 3. 함수를 호출한 주체가 허가된 관리자(executor)인지 확인합니다. 오직 관리자만이 이 기능을 실행할 수 있습니다.
        if (!(msg.sender == owner() || executor[msg.sender])) revert NotAuthorized();
        // 4. 서명이 올바른 블록체인에서 생성되었는지 확인하여 리플레이 공격을 막습니다.
        if (block.chainid != CHAIN_ID) revert BadChain();
        
        // [2단계] - 전송 요청 및 서명 데이터 유효성 검사
        // 1. 보내는 사람(from), 받는 사람(to) 주소가 유효한지, 그리고 자기 자신에게 보내는 무의미한 거래가 아닌지 확인합니다.
        if (from == address(0) || to == address(0) || from == to) revert NotAuthorized();
        // 2. 서명에 명시된 금액(p.value)과 실제 전송 요청 금액(amount)이 정확히 일치하는지 확인합니다. 1원이라도 다르면, 누군가 서명을 악용하려는 시도일 수 있으므로 즉시 거래를 중단합니다.
        if (p.value != amount) revert PermitValueMismatch();
        // 3. 서명의 유효기간이 지나지 않았는지 확인합니다. 마감 시간이 지난 서명은 사용할 수 없습니다.
        if (p.deadline < block.timestamp) revert PermitExpired();

        // [3단계] - Permit 실행
        // 사용자의 permit 서명 데이터를 토큰 컨트랙트에 전달합니다.
        // 토큰 컨트랙트는 이 서명을 검증하고, 유효하다면 from 주소의 지갑에서 이 Exchange 컨트랙트로 amount 만큼의 토큰을 보낼 수 있는 일회성 권한(allowance)을 부여합니다. 이 모든 과정은 사용자가 별도의 approve 트랜잭션을 실행할 필요 없이, 서명 하나로 이루어집니다.
        IERC20PermitLike(CURRENCY).permit(from, address(this), p.value, p.deadline, p.v, p.r, p.s);
        IERC20 erc20 = IERC20(CURRENCY);
        
        // [4단계] - 방어적 이중 검증 (Belt and Suspenders)
        // 1. permit 함수가 성공적으로 실행되었더라도, 혹시 모를 비정상적인 상황에 대비해 실제로 allowance(허용량)가 제대로 부여되었는지 다시 한번 확인합니다.
        if (erc20.allowance(from, address(this)) < amount) revert AllowanceLow();
        // 2. 보내는 사람의 지갑에 실제로 보낼 만큼의 잔고가 있는지 최종적으로 확인합니다.
        if (erc20.balanceOf(from) < amount) revert BalanceLow();

        // [5단계] - 5단계: 안전한 토큰 전송 실행
        // 1. 모든 검사를 통과했으므로, fill 함수에서도 사용했던 안전한 송금 함수(_payAndCheck)를 호출합니다. 이 함수는 수수료를 정확히 계산하고, 수수료 부과 토큰(Fee-on-Transfer) 같은 특수한 토큰까지 안전하게 처리하며 to 주소로 토큰을 전송합니다.
        uint256 fee = _payAndCheck(erc20, to, from, amount, customFeeBps);
        // 2. 토큰 전송이 성공적으로 완료되었음을 블록체인에 이벤트 로그로 남깁니다.
        emit ERC20Transferred(from, to, amount, fee);
    }

    // ---------- Internal Logic ----------
    
    // 역할: 최종 거래 조건 검증 및 실행
    // 설명: fill 함수가 기본적인 보안 검사(Nonce, 서명, 시간 등)를 통과하면, _processFill은 마치 부동산 계약 시 에스크로 담당자처럼 양측의 서류(소유권, 자금 증명 등)를 최종 확인하고 도장을 찍어 거래를 완료시키는 역할을 합니다.

    function _processFill(
        Order calldata o,
        address buyer,
        PermitData calldata p,
        bytes32 orderHash,
        uint16 customFeeBps
    ) internal {
        // [1단계] - 주문 규칙 및 참여자 유효성 검사
        // 1. 이 NFT가 우리 거래소에서 거래가 허용된 컬렉션인지 확인합니다. (화이트리스트 기능)
        if (!allowedNft[o.nft]) revert NotAllowedNFT();
        // 2. 제거됨 - taker 필드가 제거되어 모든 주문이 공개 주문으로 작동합니다.
        // 3.가격이 0인 비정상적인 거래를 막습니다.
        if (o.price == 0) revert BadPrice();
        // 4. 구매자와 판매자 주소가 유효한지, 그리고 서로 다른 사람인지 확인합니다. (자기 자신에게 판매하는 것을 방지)
        if (buyer == address(0) || o.seller == address(0) || buyer == o.seller) revert NotAuthorized();

        IERC721 nftc = IERC721(o.nft);
        IERC20 erc20 = IERC20(CURRENCY);

        // [2단계] - 판매자의 NFT 소유권 및 전송 권한 검사
        // 1. 판매자(seller)가 판매하려는 NFT(tokenId)의 실제 주인이 맞는지 NFT 컨트랙트에 직접 물어봅니다.
        if (nftc.ownerOf(o.tokenId) != o.seller) revert OwnerMismatch();
        // 2. 판매자가 이 Exchange 컨트랙트에게 자신의 NFT를 전송할 권한을 부여(approve)했는지 확인합니다. 권한 부여 방식은 두 가지입니다. 
        // 1) isApprovedForAll(이 컨트랙트에 대해 모든 NFT 전송 권한 부여) 
        // 2) getApproved(특정 NFT에 대해 전송 권한 부여)
        bool isApproved = nftc.isApprovedForAll(o.seller, address(this)) || (nftc.getApproved(o.tokenId) == address(this));
        if (!isApproved) revert NFTNotApproved();

        // [3단계] - 구매자의 토큰 지불 능력 및 허가 검사
        // 1. 구매자의 지불 허가 서명(Permit)에 적힌 금액과 NFT의 판매 가격이 정확히 일치하는지 확인합니다.
        if (p.value != o.price) revert PermitValueMismatch();
        // 2. 구매자의 지불 허가 서명이 만료되지 않았는지 확인합니다.
        if (p.deadline < block.timestamp) revert PermitExpired();
        // 3. 구매자의 서명을 이용하여, 이 컨트랙트가 구매자 지갑에서 판매 대금을 인출할 수 있는 일회성 권한을 획득합니다.
        IERC20PermitLike(CURRENCY).permit(buyer, address(this), p.value, p.deadline, p.v, p.r, p.s);

        // [4단계] - 방어적 이중 검증
        // 1. permit이 성공했더라도, 실제로 허용량(allowance)이 제대로 생겼는지 다시 한번 확인합니다.
        if (erc20.allowance(buyer, address(this)) < o.price) revert AllowanceLow();
        // 2. 구매자의 지갑에 실제로 충분한 잔고가 있는지 마지막으로 확인합니다. 이는 만에 하나 발생할 수 있는 모든 예외 상황을 막기 위한 이중 안전장치입니다.
        if (erc20.balanceOf(buyer) < o.price) revert BalanceLow();

        // [5단계] - 자산 교환 실행 및 기록
        // 1. 안전한 자금 이체 함수를 호출하여, 구매자로부터 판매자에게로 토큰을 전송하고 수수료를 처리합니다.
        uint256 fee = _payAndCheck(erc20, o.seller, buyer, o.price, customFeeBps);
        // 2. NFT 컨트랙트를 호출하여, 판매자로부터 구매자에게로 NFT를 전송합니다. safeTransferFrom을 사용하여 받는 사람이 NFT를 안전하게 받을 수 있는 주소인지 확인합니다.
        nftc.safeTransferFrom(o.seller, buyer, o.tokenId);
        // 3. 모든 과정이 성공적으로 끝났음을 알리는 OrderFilled 이벤트를 발생시켜 블록체인에 거래 완료 기록을 남깁니다.
        _emitFilled(orderHash, o.seller, buyer, o.nft, o.tokenId, o.price, fee, customFeeBps);
    }

    // Fee-on-Transfer 토큰을 방어하며 토큰을 전송하는 함수
    // 역할: 단순히 돈을 보내는 것(pay)에서 그치지 않고, 돈이 정확하게 전달되었는지 반드시 확인(check)하는 매우 중요한 보안 기능을 수행
    // 왜 '확인(Check)'이 필요한가요? - Fee-on-Transfer (FoT) 토큰의 함정
    // 전송(transfer)할 때마다 수수료를 떼어가는 특이한 ERC-20 토큰들이 있습니다. 예를 들어, 100개를 보내면 받는 사람은 98개만 받게 되는 식이죠. 이를 Fee-on-Transfer(FoT) 토큰이라고 합니다
    // 일반적인 거래소가 이런 토큰을 다룬다면 큰 문제가 생깁니다.
    // 문제 상황: 판매자가 FoT 토큰으로 100개를 받기로 하고 NFT를 팔았습니다. 구매자는 100개를 보냈지만, 토큰 자체 수수료 때문에 판매자는 98개만 받습니다. 판매자는 약속된 금액을 받지 못해 손해를 봅니다.
    // _payAndCheck 함수는 바로 이런 상황을 막기 위해 설계되었습니다.
    function _payAndCheck(
        IERC20 erc20,
        address recipient,
        address payer,
        uint256 price,
        uint16 _feeBps
    ) internal returns (uint256 fee) {
        // [1단계] - 수수료 계산
        // 1. 거래소의 플랫폼 수수료(fee)와 판매자가 실제로 받을 금액(toRecipient)을 계산합니다.
        fee = (_feeBps == 0) ? 0 : (price * _feeBps) / 10_000;
        uint256 toRecipient = price - fee;
        if (fee > 0 && feeTo == address(0)) revert FeeToZero();

        // [2단계] - 이체 전 잔액 스냅샷 촬영
        // 1. 돈을 보내기 전 판매자의 토큰 잔액을 미리 저장해 둡니다.
        uint256 recipientBalBefore = erc20.balanceOf(recipient);
        // 2. 수수료 지갑의 잔액도 미리 저장해 둡니다.
        uint256 feeToBalBefore = (fee > 0) ? erc20.balanceOf(feeTo) : 0;

        // [3단계] - 자금 이체 실행
        if (toRecipient > 0) erc20.safeTransferFrom(payer, recipient, toRecipient);
        if (fee > 0) erc20.safeTransferFrom(payer, feeTo, fee);

        // [4단계] - 이체 후 잔액 검증
        // 1. 이체 후에 판매자의 잔액이 실제로 얼마나 늘어났는지를 계산합니다.
        uint256 recipientDelta = erc20.balanceOf(recipient) - recipientBalBefore;
        if (fee == 0) {
            // 2. 만약 실제로 늘어난 금액(recipientDelta)이 약속된 금액(toRecipient)과 단 1이라도 다르다면, 이는 토큰 자체에서 수수료를 떼어갔다는 의미입니다. 이 경우, FoTDetected 에러를 발생시키며 거래 전체를 즉시 취소시켜 모든 참여자를 보호합니다.
            if (recipientDelta != toRecipient) revert FoTDetected();
        } else {
            if (feeTo == recipient) {
                if (recipientDelta != (toRecipient + fee)) revert FoTDetected();
            } else {
                if (recipientDelta != toRecipient) revert FoTDetected();
                uint256 feeDelta = erc20.balanceOf(feeTo) - feeToBalBefore;
                if (feeDelta != fee) revert FoTDetected();
            }
        }
    }

    function _emitFilled(
        bytes32 orderHash,
        address seller,
        address buyer,
        address nft,
        uint256 tokenId,
        uint256 price,
        uint256 fee,
        uint16 feeBps
    ) internal {
        emit OrderFilled(orderHash, seller, buyer, nft, tokenId, CURRENCY, price, fee, feeBps);
    }

    // ---------- Native guard ----------
    receive() external payable { revert NoNative(); }
    fallback() external { revert NoNative(); }
}