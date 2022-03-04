// SPDX-License-Identifier: https://multiverseexpert.com/
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract EPICGatheringAvatar is
    ERC721,
    ERC721URIStorage,
    ERC721Enumerable,
    Ownable,
    AccessControl,
    Pausable
{
    using SafeMath for uint256;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant LOCKER_ROLE = keccak256("LOCKER_ROLE");

    address public recipient;
    string private baseURI = "";
    uint256[] private arrTemp;
    uint256[] private indexClan;

    struct Clan {
        string name;
        bool open;
        uint256[] tokenId;
    }

    struct RedeemToken {
        uint256 amount;
        bool status;
    }

    mapping(uint256 => Clan) clans;
    mapping(address => RedeemToken) public redeemToken;
    mapping(uint256 => bool) public tokenLock;

    event tokenReceived(uint256 tokenId);

    constructor(string memory name, string memory symbol) ERC721(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(LOCKER_ROLE, msg.sender);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC721, ERC721Enumerable, AccessControl)
        returns (bool)
    {
        return
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function _baseURI()
        internal
        view
        virtual
        override(ERC721)
        returns (string memory)
    {
        return baseURI;
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function setRedeemToken(address token, uint256 amount) public onlyOwner {
        redeemToken[token] = RedeemToken(amount, true);
    }

    function updateRedeemToken(address token, uint256 amount) public onlyOwner {
        redeemToken[token].amount = amount;
    }

    function getRedeemToken(address token)
        public
        view
        returns (RedeemToken memory)
    {
        return redeemToken[token];
    }

    function openRedeemToken(address token, bool status) public onlyOwner {
        redeemToken[token].status = status;
    }

    function setRecipient(address wallet) public onlyOwner {
        recipient = wallet;
    }

    function setClan(uint256 index, string memory name) public onlyOwner {
        require(
            bytes(clans[index].name).length == 0,
            "Clan: clans is already exist"
        );
        clans[index] = Clan(name, false, arrTemp);
        indexClan.push(index);
    }

    function openClan(uint256 index, bool status) public onlyOwner {
        clans[index].open = status;
    }

    function getAllClan() public view returns (uint256[] memory) {
        return indexClan;
    }

    function getClan(uint256 index) public view returns (Clan memory) {
        return clans[index];
    }

    function getClanByTokenId(uint256 token) public view returns (Clan memory) {
        uint256 index = token.div(10000);
        return clans[index];
    }

    function safeMint(
        address owner,
        string memory uri,
        uint256 tokenId
    ) public whenNotPaused onlyRole(MINTER_ROLE) {
        uint256 index = tokenId.div(10000);
        require(bytes(clans[index].name).length != 0, "Clan: clans don't have");

        _safeMint(owner, tokenId);
        _setTokenURI(tokenId, uri);
        tokenLock[tokenId] = false;

        if (owner == address(this)) {
            clans[index].tokenId.push(tokenId);
        }
    }

    function burn(uint256 tokenId) public whenNotPaused {
        _burn(tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        override(ERC721, ERC721URIStorage)
    {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function buy(uint256 clan, address token) public whenNotPaused {
        IERC20 _token = IERC20(token);
        require(getRedeemToken(token).status == true, "Token isn't listed");

        require(bytes(clans[clan].name).length != 0, "Clan: clans don't have");
        require(clans[clan].open == true, "Clan: clans isn't open");
        require(
            balanceOf(msg.sender) < 5,
            "Avatar: Maximum hold only 5 avatars per wallet"
        );
        require(
            _token.balanceOf(msg.sender) >= getRedeemToken(token).amount,
            "Token: Token not enough"
        );

        _token.transferFrom(
            msg.sender,
            recipient,
            getRedeemToken(token).amount
        );

        uint256 _random = uint256(
            keccak256(
                abi.encodePacked(
                    "EPIC",
                    block.difficulty,
                    block.timestamp,
                    block.number,
                    block.difficulty
                )
            )
        );
        uint256 _index = _random.mod(clans[clan].tokenId.length);
        uint256 tokenId = clans[clan].tokenId[_index];

        _setApprovalForAll(address(this), msg.sender, true);
        safeTransferFrom(address(this), msg.sender, tokenId, "0x00");
        _setApprovalForAll(address(this), msg.sender, false);

        clans[clan].tokenId[_index] = clans[clan].tokenId[
            clans[clan].tokenId.length - 1
        ];
        clans[clan].tokenId.pop();

        emit tokenReceived(tokenId);
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function lockToken(uint256 token) public onlyRole(LOCKER_ROLE) {
        tokenLock[token] = true;
    }

    function unlockToken(uint256 token) public onlyRole(LOCKER_ROLE) {
        tokenLock[token] = false;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal override(ERC721, ERC721Enumerable) whenNotPaused {
        require(tokenLock[tokenId] == false, "Avatar: Token locked");
        super._beforeTokenTransfer(from, to, tokenId);
    }
}
