// SPDX-License-Identifier: https://multiverseexpert.com/
pragma solidity ^0.8.2;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/IERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";

interface IChainSeed {
    function grantWhitelist(address _owner, bool _active) external;

    function randomSeed() external returns (bytes32 seed);
}

interface IPrevAvatar {
    function totalSupply() external view returns (uint256);

    function tokenOfOwnerByIndex(address owner, uint256 index)
        external
        view
        returns (uint256);

    function tokenByIndex(uint256 index) external view returns (uint256);

    function ownerOf(uint256 tokenId) external view returns (address owner);
}

contract EPICGatheringAvatarV1 is
    ERC721Upgradeable,
    ERC721URIStorageUpgradeable,
    ERC721EnumerableUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant LOCKER_ROLE = keccak256("LOCKER_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");

    address public recipient;
    string public baseURI;

    uint256[] private indexClans;

    IChainSeed chainSeed;

    struct Clan {
        string name;
        bool isOpen;
        uint256[] tokenId;
        bool isExist;
    }

    struct TokenWhitelist {
        uint256 amount;
        uint256 whitelistAmount;
        bool isUse;
    }

    struct UserClan {
        uint256 clanId;
        bool isExist;
    }

    mapping(uint256 => Clan) public clans;
    mapping(uint256 => bool) public tokenLock;
    mapping(address => bool) public whiteListAccount;

    mapping(address => UserClan) public userClanExist;
    mapping(address => TokenWhitelist) public tokenWhitelists;

    mapping(uint256 => mapping(uint256 => bool)) public isTokenClanExist;
    event tokenReceived(uint256 tokenId);

    function initialize(
        string memory _name,
        string memory _symbol,
        address _seedAddress,
        string memory _baseURI
    ) public initializer {
        __ERC721_init(_name, _symbol);
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(LOCKER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        recipient = msg.sender;
        chainSeed = IChainSeed(_seedAddress);
        baseURI = _baseURI;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(
            ERC721Upgradeable,
            ERC721EnumerableUpgradeable,
            AccessControlUpgradeable
        )
        returns (bool)
    {
        return
            interfaceId == type(IERC721Upgradeable).interfaceId ||
            interfaceId == type(IERC721MetadataUpgradeable).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function pause() public onlyRole(DEFAULT_ADMIN_ROLE) onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause()
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
        onlyRole(PAUSER_ROLE)
    {
        _unpause();
    }

    function setRecipient(address wallet) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(wallet != address(0), "Recipient: non zero address");
        recipient = wallet;
    }

    function setWhitelistToken(
        address token,
        uint256 amount,
        uint256 whitelist
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        tokenWhitelists[token] = TokenWhitelist(amount, whitelist, true);
    }

    function updateWhitelistToken(
        address token,
        uint256 amount,
        uint256 whitelist
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        tokenWhitelists[token].amount = amount;
        tokenWhitelists[token].whitelistAmount = whitelist;
    }

    function openWhitelistToken(address token, bool use)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        tokenWhitelists[token].isUse = use;
    }

    function getWhitelistToken(address token)
        public
        view
        returns (TokenWhitelist memory)
    {
        return tokenWhitelists[token];
    }

    function setClan(uint256 index, string memory name)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        uint256[] memory initToken;
        require(bytes(name).length != 0, "Clan: name is empty");
        require(clans[index].isExist == false, "Clan: already exist");
        clans[index] = Clan(name, false, initToken, true);
        indexClans.push(index);
    }

    function existClan(uint256 index, bool exist)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        clans[index].isExist = exist;
    }

    function openClan(uint256 index, bool open)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        clans[index].isOpen = open;
    }

    function getAllClans() public view returns (uint256[] memory) {
        return indexClans;
    }

    function getClan(uint256 index) public view returns (Clan memory) {
        return clans[index];
    }

    function getClanByTokenId(uint256 token) public view returns (Clan memory) {
        uint256 index = token.div(10000);
        return clans[index];
    }

    function addClanToken(uint256 index, uint256[] memory tokenId)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(clans[index].isExist == true, "Clan: don't already exist");
        require(tokenId.length > 0, "Token: is empty");

        for (uint256 i = 0; i < tokenId.length; i++) {
            if (isTokenClanExist[index][tokenId[i]] == false) {
                isTokenClanExist[index][tokenId[i]] = true;
                clans[index].tokenId.push(tokenId[i]);
            }
        }
    }

    function safeMint(address owner, uint256 tokenId) private whenNotPaused {
        uint256 index = tokenId.div(10000);
        require(clans[index].isExist == true, "Clan: don't already exist");

        _safeMint(owner, tokenId);
        _setTokenURI(
            tokenId,
            string(
                abi.encodePacked(
                    baseURI,
                    StringsUpgradeable.toString(tokenId),
                    ".json"
                )
            )
        );
        tokenLock[tokenId] = false;
    }

    function burn(uint256 tokenId) public whenNotPaused {
        require(
            msg.sender == ownerOf(tokenId),
            "Avater: not owned this avatar"
        );
        _burn(tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        override(ERC721Upgradeable, ERC721URIStorageUpgradeable)
    {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721Upgradeable, ERC721URIStorageUpgradeable)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function buy(uint256 clanId, address token)
        public
        whenNotPaused
        nonReentrant
    {
        IERC20Upgradeable _token = IERC20Upgradeable(token);
        require(getWhitelistToken(token).isUse == true, "Token: isn't listed");

        require(clans[clanId].isExist == true, "Clan: don't already exist");
        require(clans[clanId].isOpen == true, "Clan: isn't open");

        require(
            balanceOf(msg.sender) < 5,
            "Avatar: Maximum hold only 5 avatars per wallet"
        );

        require(
            _token.balanceOf(msg.sender) >= getWhitelistToken(token).amount,
            "Token: not enough"
        );

        require(recipient != address(0), "Recipient: non zero address");

        if (!userClanExist[msg.sender].isExist) {
            userClanExist[msg.sender] = UserClan(clanId, true);
        } else {
            require(
                userClanExist[msg.sender].clanId == clanId,
                "Avatar: Maximum hold only 1 clan"
            );
        }

        require(clans[clanId].tokenId.length > 0, "Avatar: not available");

        _token.safeTransferFrom(
            msg.sender,
            recipient,
            getWhitelistToken(token).amount
        );

        chainSeed.grantWhitelist(address(this), true);

        bytes32 randomSeed = chainSeed.randomSeed();

        uint256 _random = uint256(
            keccak256(
                abi.encodePacked(
                    "EPIC",
                    block.difficulty,
                    block.timestamp,
                    block.number,
                    block.difficulty,
                    randomSeed
                )
            )
        );

        chainSeed.grantWhitelist(address(this), false);

        uint256 _index = _random.mod(clans[clanId].tokenId.length);
        uint256 tokenId = clans[clanId].tokenId[_index];

        safeMint(msg.sender, tokenId);

        clans[clanId].tokenId[_index] = clans[clanId].tokenId[
            clans[clanId].tokenId.length - 1
        ];
        clans[clanId].tokenId.pop();

        emit tokenReceived(tokenId);
    }

    function buyWithWhitelist(uint256 clanId, address token)
        public
        whenNotPaused
        nonReentrant
        onlyRole(WHITELIST_ROLE)
    {
        IERC20Upgradeable _token = IERC20Upgradeable(token);
        require(getWhitelistToken(token).isUse == true, "Token: isn't listed");

        require(clans[clanId].isExist == true, "Clan: don't already exist");
        require(clans[clanId].isOpen == true, "Clan: isn't open");

        require(
            balanceOf(msg.sender) < 5,
            "Avatar: Maximum hold only 5 avatars per wallet"
        );

        require(
            _token.balanceOf(msg.sender) >=
                getWhitelistToken(token).whitelistAmount,
            "Token: not enough"
        );

        require(recipient != address(0), "Recipient: non zero address");

        if (!userClanExist[msg.sender].isExist) {
            userClanExist[msg.sender] = UserClan(clanId, true);
        } else {
            require(
                userClanExist[msg.sender].clanId == clanId,
                "Avatar: Maximum hold only 1 clan"
            );
        }

        require(clans[clanId].tokenId.length > 0, "Avatar: not available");

        _token.safeTransferFrom(
            msg.sender,
            recipient,
            getWhitelistToken(token).whitelistAmount
        );

        chainSeed.grantWhitelist(address(this), true);

        bytes32 randomSeed = chainSeed.randomSeed();

        uint256 _random = uint256(
            keccak256(
                abi.encodePacked(
                    "EPIC",
                    block.difficulty,
                    block.timestamp,
                    block.number,
                    block.difficulty,
                    randomSeed
                )
            )
        );

        chainSeed.grantWhitelist(address(this), false);

        uint256 _index = _random.mod(clans[clanId].tokenId.length);
        uint256 tokenId = clans[clanId].tokenId[_index];

        safeMint(msg.sender, tokenId);

        clans[clanId].tokenId[_index] = clans[clanId].tokenId[
            clans[clanId].tokenId.length - 1
        ];
        clans[clanId].tokenId.pop();

        _revokeRole(WHITELIST_ROLE, msg.sender);

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

    function lockToken(uint256 token, bool status)
        public
        onlyRole(LOCKER_ROLE)
    {
        tokenLock[token] = status;
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    )
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        whenNotPaused
    {
        require(tokenLock[tokenId] == false, "Avatar: Token locked");
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function migrate() public whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        IPrevAvatar _prev = IPrevAvatar(
            0xbd2A4c57800A30a02E70bd019b9bc87B92586286
        );

        require(
            _prev.totalSupply() != totalSupply(),
            "Avatar: Maximum migrate"
        );

        for (uint256 total = 0; total < _prev.totalSupply(); total++) {
            uint256 tokenId = _prev.tokenByIndex(total);
            address owner = _prev.ownerOf(tokenId);

            _safeMint(owner, tokenId);
            _setTokenURI(
                tokenId,
                string(
                    abi.encodePacked(
                        baseURI,
                        StringsUpgradeable.toString(tokenId),
                        ".json"
                    )
                )
            );
            tokenLock[tokenId] = false;
        }
    }

    function getTokensByOwner(address owner)
        public
        view
        returns (uint256[] memory)
    {
        uint256 balance = balanceOf(owner);
        uint256[] memory tokenId = new uint256[](balance);
        for (uint256 index = 0; index < balance; index++) {
            tokenId[index] = uint256(tokenOfOwnerByIndex(owner, index));
        }

        return tokenId;
    }
}
