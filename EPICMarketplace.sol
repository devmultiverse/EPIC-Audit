// SPDX-License-Identifier: https://multiverseexpert.com/
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
interface IERC20 {
    function mint(address to, uint256 amount) external;
    function transferFrom(address sender, address recipient, uint256 amount) external;
    function balanceOf(address account) external returns(uint256);
    function approve(address spender, uint256 amount) external returns(bool);
    function allowance(address owner, address spender) external returns(uint256);
}
interface IERC1155 {
    function balanceOf(address account, uint256 id) external returns(uint256);
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes memory data) external;
    function isApprovedForAll(address account, address operator) external returns(bool);
    function supportsInterface(bytes4 interfaceId) external returns(bool);
}
interface IERC721 {
    function balanceOf(address owner) external returns(uint256);
    function ownerOf(uint256 tokenId) external returns(address);
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function isApprovedForAll(address account, address operator) external returns(bool);
    function supportsInterface(bytes4 interfaceId) external returns(bool);
}
interface ITOKEN{
    function _getWhiteList(address token) external view returns(bool);
    function getFee(uint256 price) external view returns (uint256);
}
interface IAVATAR{
    function lockToken(uint256 token) external;
    function unlockToken(uint256 token) external;
}
contract EpicMarket is AccessControl, Pausable {
    using Counters for Counters.Counter;
    Counters.Counter private _marketIdCounter;
    address public _wallet;
    ITOKEN wlToken;
    enum TokenType {
        CLOSED,
        ERC1155,
        ERC721
    }
    bytes4 public constant ERC1155InterfaceId = 0xd9b67a26;
    bytes4 public constant ERC721InterfaceId = 0x80ac58cd;
    struct Item {
        address _item;
        TokenType _itemType;
        address _owner;
        uint256 _tokenId;
        uint256 _amount;
        uint256 _price;
        uint256 _expiration;
        address _buyer;
        bool _available;
        uint256 _marketId;
        address _token;
    }
    struct Offer {
        address _buyer;
        uint256 _price;
        uint256 _amount;
        uint256 _marketId;
        uint256 _expiration;
        uint256 _offerId;
        bool _isAccept;
        bool _active;
    }

    Item[] items;
    // mapping owner -> offer[]
    mapping(address => Offer[]) offers;

    // event 
    event PlaceItem(address item, uint256 price, uint256 marketId, uint256 tokenId, uint256 amount);
    event BuyItem(uint256 marketId, uint256 tokenId, uint256 amount, uint256 price, address seller, address buyer);
    event CancelItem(uint256 marketId, address owner, uint256 price);
    event CloseOffer(uint256 marketId, uint256 offerId);
    event ExistItem(address item, address owner, bool status);
    event MakeOffer(uint256 marketId, uint256 amount, uint256 price, bool status);

    function pause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }
    function unpause() public onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }
    modifier onlyExistItem(uint256 marketId) {
        (bool found, Item memory itemData) = _getItemInfo(marketId);
        require(found, "Item is not exist");
        require(itemData._available, "Item is not available");
        require(itemData._expiration >= block.timestamp, "This item has expired");
        _;
    }
    modifier uniqueItem(address item, uint256 tokenId, uint256 amount) {
        for(uint256 i = 0; i < items.length; i++){
            if(
                items[i]._amount == amount &&
                items[i]._item == item &&
                items[i]._tokenId == tokenId &&
                items[i]._available &&
                items[i]._owner == msg.sender
            ) revert("This item is already created");
                
        }
        _;
    }
    modifier onlyItemOwner(uint256 marketId) {
        (bool found, Item memory itemData) = _getItemInfo(marketId);
        require(found, "Not found token");
        bool isERC721 = IERC721(itemData._item).supportsInterface(ERC721InterfaceId);
        bool isERC1155 = IERC1155(itemData._item).supportsInterface(ERC1155InterfaceId);
        require(
            (isERC721 && IERC721(itemData._item).ownerOf(itemData._tokenId) == msg.sender) || 
            (isERC1155 && IERC1155(itemData._item).balanceOf(itemData._owner, itemData._tokenId) >= itemData._amount)
            , "You are not owned this token."
        );
        _;
    }
    function _getItemInfo(uint256 marketId) public view returns(bool, Item memory) {
        Item memory itemData = items[marketId];
        if(itemData._item == address(0)) return (false, itemData);
        return(true, itemData);
    }
    constructor(address tokenWhiteList) {
        wlToken = ITOKEN(tokenWhiteList);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _wallet = msg.sender;
    }
    function placeItem(
        address item,
        uint256 tokenId,
        uint256 amount,
        uint256 price, // wei
        uint256 expiration,
        address token
    ) public whenNotPaused uniqueItem(item, tokenId, amount){
        TokenType itemType = TokenType.CLOSED;
        require(amount >= 1, "Amount must be greater or equal than 1");
        require(price > 0, "Price must more than zero");
        require(wlToken._getWhiteList(token), "Token is not in white list");
        require(IERC20(token).balanceOf(msg.sender) >= wlToken.getFee(price), "Balance is not enough to pay fee");
        IAVATAR(item).lockToken(tokenId);
        IERC20(token).transferFrom(msg.sender, _wallet, wlToken.getFee(price));
        if(IERC1155(item).supportsInterface(ERC1155InterfaceId))
            itemType = TokenType.ERC1155;
        if(IERC721(item).supportsInterface(ERC721InterfaceId))
            itemType = TokenType.ERC721;
        if(itemType == TokenType.ERC1155){
            require(IERC1155(item).balanceOf(msg.sender, tokenId) >= amount, "You do not own this item (ERC1155)");
            require(IERC1155(item).isApprovedForAll(msg.sender, address(this)), "Item is not approve");
        } else if(itemType == TokenType.ERC721) {
            require(IERC721(item).ownerOf(tokenId) == msg.sender, "You do not own this item (ERC721)");
            require(IERC721(item).isApprovedForAll(msg.sender, address(this)), "Item is not approve");
        } else {
            revert("Item type is incorrect");
        }
        require(expiration > block.timestamp, "Incorrect expiration");

        uint256 marketId = _marketIdCounter.current();
        _marketIdCounter.increment();
        items.push(
            Item(
                item,
                itemType,
                msg.sender,
                tokenId,
                amount,
                price, // wei
                expiration,
                address(0),
                true,
                marketId,
                token
            )
        );


        emit PlaceItem(item, price, marketId, tokenId, amount);
    }
    function buyItem(uint256 marketId, uint256 amount) public whenNotPaused onlyExistItem(marketId) {
        (, Item memory itemData) = _getItemInfo(marketId);
        require(IERC20(itemData._token).balanceOf(msg.sender) >= itemData._price * amount, "Balance is not enough");
        require(itemData._buyer == address(0), "Item is already sold");
        require(amount <= itemData._amount, "Item is not enough");
        require(msg.sender != itemData._owner, "You already owned this item");
        IAVATAR(itemData._item).unlockToken(itemData._tokenId);
        if(itemData._itemType == TokenType.ERC1155)
            require(
                IERC1155(itemData._item).balanceOf(itemData._owner, itemData._tokenId) >= itemData._amount,
                "Seller does not own this item (ERC1155)"
            );
        if(itemData._itemType == TokenType.ERC721)
            require(
                IERC721(itemData._item).ownerOf(itemData._tokenId) == itemData._owner,
                "Seller does not own this item (ERC721)"
            );
        IERC20(itemData._token).transferFrom(msg.sender, itemData._owner, itemData._price * amount);
        if(itemData._itemType == TokenType.ERC1155) 
            IERC1155(itemData._item).safeTransferFrom(
                itemData._owner, 
                msg.sender, 
                itemData._tokenId, 
                amount, 
                ""
            );
        // transfer ERC721 to buyer
        if(itemData._itemType == TokenType.ERC721)
            IERC721(itemData._item).safeTransferFrom(
                itemData._owner, 
                msg.sender, 
                itemData._tokenId
            );
        if(itemData._amount == amount){
            items[marketId]._available = false;
            items[marketId]._buyer = msg.sender;
        }
        items[marketId]._amount -= amount;
        emit BuyItem(marketId, itemData._tokenId, amount, itemData._price * amount, itemData._owner, msg.sender);
    }
    function makeOffer(uint256 marketId, uint256 price, uint256 expiration, uint256 amount) public whenNotPaused onlyExistItem(marketId){
        require(block.timestamp < expiration, "Offer is expired");
        (, Item memory itemData) = _getItemInfo(marketId);
        require(price * amount <= IERC20(itemData._token).balanceOf(msg.sender), "Balance is not enough");
        require(itemData._amount >= amount, "Amount item is not enough");
        require(itemData._buyer == address(0), "Item is already sold");
        require(amount > 0, "Amount is incorrect");
        require(itemData._owner != msg.sender, "You already owned this item");
        offers[itemData._owner].push(
            Offer(
                msg.sender,
                price,
                amount,
                marketId,
                expiration,
                offers[itemData._owner].length,
                false,
                true
            )
        );
        emit MakeOffer(marketId, amount, price * amount, true);
    }
    function getItems() public view returns(Item[] memory){
        return items;
    }
    function getOfferLists(address owner) public view returns (Offer[] memory){
        return offers[owner];
    }
    function getOfferById(address owner, uint256 offerId) public view returns(bool status, Offer memory){
        return (true, offers[owner][offerId]);
    }
    function acceptOffer(uint256 marketId, uint256 offerId) public whenNotPaused onlyExistItem(marketId){
        (, Item memory itemData) = _getItemInfo(marketId);
        require(itemData._buyer == address(0), "Item is already sold");
        IAVATAR(itemData._item).unlockToken(itemData._tokenId);
        (bool status, Offer memory offerData) = getOfferById(itemData._owner, offerId);
        require(status, "Offer not found");
        require(offerData._active, "Offer is not active");
        require(offerData._isAccept == false, "Item is already accept");
        require(offerData._expiration >= block.timestamp, "Offer is expired");
        require(msg.sender == itemData._owner, "You can't accept this offer");
        require(itemData._amount >= offerData._amount, "Item in market is not enough");
        require(IERC20(items[marketId]._token).balanceOf(offerData._buyer) >= offerData._price * offerData._amount, "Balance buyer is not enough");
        IERC20(itemData._token).transferFrom(offerData._buyer, itemData._owner, offerData._price * offerData._amount);

        if(itemData._itemType == TokenType.ERC1155){
            IERC1155(itemData._item).safeTransferFrom(itemData._owner, offerData._buyer, itemData._tokenId, offerData._amount, "");
        } else if(itemData._itemType == TokenType.ERC721){
            IERC721(itemData._item).safeTransferFrom(itemData._owner, offerData._buyer, itemData._tokenId);
        } else {
            revert("Item type is incorrect");
        }
        if(offerData._amount == itemData._amount){  
            items[marketId]._available = false;
            items[marketId]._buyer = offerData._buyer;
        }
        items[marketId]._amount -= offerData._amount;
        offers[itemData._owner][offerId]._isAccept = true;
        offers[itemData._owner][offerId]._active = false;
    }
    function closeOffer(uint256 offerId, uint256 marketId) public whenNotPaused onlyExistItem(marketId){
        address itemOwner = items[marketId]._owner;
        require(offerId < offers[itemOwner].length, "Invalid offerId");
        require(offers[itemOwner][offerId]._buyer == msg.sender, "You can't close this offer");
        // collect fee to wallet owner
        uint256 fee = wlToken.getFee(offers[itemOwner][offerId]._price);
        require(IERC20(items[marketId]._token).balanceOf(msg.sender) >= fee, "Balance is not enough to pay fee");
        IERC20(items[marketId]._token).transferFrom(msg.sender, _wallet, fee);

        offers[itemOwner][offerId]._active = false;
        emit CloseOffer(marketId, offerId);
    }
    function cancelItem(uint256 marketId) public whenNotPaused onlyItemOwner(marketId)  {
        (, Item memory itemData) = _getItemInfo(marketId);
        require(items[marketId]._available, "Items is already not available");
        require(msg.sender == itemData._owner, "You can't cancel this item");
        emit CancelItem(itemData._marketId, itemData._owner, itemData._price);
        items[marketId]._available = false;
        IAVATAR(itemData._item).unlockToken(itemData._tokenId);
        // transfer fee to admin wallet
    }
    function setAdminWallet(address wallet) public whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        _wallet = wallet;
    }
    function getMarketId(address item, address owner, uint256 tokenId, uint256 amount, bool status) public view returns(bool, uint256){
        for(uint i = 0; i < items.length; i++){
            if(items[i]._available == status && items[i]._owner == owner && items[i]._tokenId == tokenId && items[i]._amount == amount && items[i]._item == item){
                return (true, items[i]._marketId);
            }
        }
        return (false, 0);
    }
    function setAvailable(uint256 marketId) public whenNotPaused onlyExistItem(marketId) onlyRole(DEFAULT_ADMIN_ROLE) returns (bool){
        items[marketId]._available = false;
        return true;
    }
}