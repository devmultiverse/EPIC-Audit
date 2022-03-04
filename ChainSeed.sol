// contracts/ChainSeed.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface IChainLink {
    // Latest Data-Feed
    function latestRoundData()
        external
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    function latestRound() external returns (uint256 roundId);

    // Historical Data-Feed
    function getAnswer(uint256 _roundId) external returns (int256 answer);

    function getRoundData(uint80 _roundId)
        external
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );

    function getTimestamp(uint256 _roundId)
        external
        returns (uint256 updatedAt);
}

/// @custom:security-contact siriwat576@gmail.com
contract ChainSeed is AccessControl, ReentrancyGuard {
    bytes32 public constant DEV_ROLE = keccak256("DEV_ROLE");

    uint256 private _nonce;
    uint256 private _feedCount;
    mapping(address => bool) private _dataFeeds;
    mapping(address => bool) private _whitelists;
    address[] private _providers;
    bytes32 private _lastSeed;

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(DEV_ROLE, msg.sender);
    }

    // Modifier
    modifier onlyWhitelist() {
        require(_whitelists[msg.sender], "WHITELIST: Forbidden");
        _;
    }

    // Developer
    function addTrustedSource(address[] memory _provider)
        public
        onlyRole(DEV_ROLE)
        nonReentrant
    {
        require(_provider.length > 0, "SEED: No provider provided");
        for (uint256 i = 0; i < _provider.length; i++) {
            if (_provider[i] == address(0))
                revert("SEED: Provider address must not be zero");
            if (_provider[i] == address(this))
                revert("SEED: Provider address is not valid");
            if (_dataFeeds[_provider[i]])
                revert("SEED: Provider is already listed");

            _feedCount++;
            _dataFeeds[_provider[i]] = true;

            if (!_isProviderExists(_provider[i])) _providers.push(_provider[i]);
        }
    }

    function removeTrustedSource(address[] memory _provider)
        public
        onlyRole(DEV_ROLE)
        nonReentrant
    {
        for (uint256 i = 0; i < _provider.length; i++) {
            if (!_dataFeeds[_provider[i]]) revert("SEED: No provider found");

            _feedCount--;
            _dataFeeds[_provider[i]] = false;
        }
    }

    function grantWhitelist(address _owner, bool _active)
        public
        onlyRole(DEV_ROLE)
    {
        require(
            _owner != address(this) && _owner != address(0),
            "WHITELIST: Invalid owner"
        );
        require(_whitelists[_owner] != _active, "WHITELIST: Invalid status");

        _whitelists[_owner] = _active;
    }

    // Public
    function randomSeed()
        public
        onlyWhitelist
        nonReentrant
        returns (bytes32 seed)
    {
        return _secureRandomSeed();
    }

    // Private
    function _getProviders() private view returns (address[] memory) {
        uint256 size = 0;
        for (uint256 i = 0; i < _providers.length; i++) {
            address provider = _providers[i];
            if (_dataFeeds[provider]) size++;
        }

        address[] memory providers = new address[](size);

        uint256 counter = 0;
        for (uint256 i = 0; i < _providers.length; i++) {
            address provider = _providers[i];
            if (_dataFeeds[provider]) {
                providers[counter] = provider;
                counter++;
            }
        }
        return providers;
    }

    function _secureRandomSeed() private returns (bytes32 seed) {
        address[] memory providers = _getProviders();
        require(providers.length > 0, "RANDOM: No providers found");

        uint256 providerIndex = uint256(
            keccak256(
                abi.encodePacked(block.number, msg.sender, _lastSeed, _nonce)
            )
        ) % providers.length;

        IChainLink dataFeed = IChainLink(providers[providerIndex]);

        (uint80 roundId, int256 answer, , uint256 updatedAt, ) = dataFeed
            .latestRoundData();

        bytes32 finalSeed = _getSeed(answer, updatedAt, roundId);

        // New Linked-Seed
        uint256 seedLoopCount = (roundId % providerIndex) +
            ((roundId + block.number + uint256(finalSeed)) % providerIndex);
        _lastSeed = _getHashLoop(seedLoopCount, finalSeed);

        // Increase nonce
        _nonce++;

        return finalSeed;
    }

    function _getSeed(
        int256 answer,
        uint256 updatedAt,
        uint80 roundId
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    answer,
                    updatedAt,
                    roundId,
                    _lastSeed,
                    msg.sender
                )
            );
    }

    function _getHashLoop(uint256 _count, bytes32 _seed)
        private
        view
        returns (bytes32)
    {
        bytes32 rootHash = keccak256(
            abi.encodePacked(block.timestamp, msg.sender, _lastSeed, _nonce)
        );
        bytes32 linkedSeed = rootHash;
        for (uint256 i = 0; i < _count; i++) {
            bytes32 newSeed = keccak256(
                abi.encodePacked(i, linkedSeed, _lastSeed, _seed)
            );
            linkedSeed = newSeed;
        }
        return linkedSeed;
    }

    function _isProviderExists(address _provider) private view returns (bool) {
        for (uint256 i = 0; i < _providers.length; i++)
            if (_providers[i] == _provider) return true;
        return false;
    }
}
