// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./a/Initializable.sol";
import "./a/ReentrancyGuardUpgradeable.sol";
import "./a/Constants.sol";
import "./a/FoundationTreasuryNode.sol";
import "./a/NFTMarketAuction.sol";
import "./a/NFTMarketBuyPrice.sol";
import "./a/NFTMarketCore.sol";
import "./a/NFTMarketFees.sol";
import "./a/NFTMarketOffer.sol";
import "./a/NFTMarketPrivateSaleGap.sol";
import "./a/NFTMarketReserveAuction.sol";
import "./a/SendValueWithFallbackWithdraw.sol";
contract FNDNFTMarket is
  Initializable,
  FoundationTreasuryNode,
  NFTMarketCore,
  ReentrancyGuardUpgradeable,
  SendValueWithFallbackWithdraw,
  NFTMarketFees,
  NFTMarketAuction,
  NFTMarketReserveAuction,
  NFTMarketPrivateSaleGap,
  NFTMarketBuyPrice,
  NFTMarketOffer
{
  constructor(
    address payable treasury,
    address feth,
    address royaltyRegistry,
    uint256 duration
  )
    FoundationTreasuryNode(treasury)
    NFTMarketCore(feth)
    NFTMarketFees(royaltyRegistry)
    NFTMarketReserveAuction(duration) // solhint-disable-next-line no-empty-blocks
  {}
  function initialize() external initializer {
    NFTMarketAuction._initializeNFTMarketAuction();
  }
  function _beforeAuctionStarted(address nftContract, uint256 tokenId)
    internal
    override(NFTMarketCore, NFTMarketBuyPrice, NFTMarketOffer)
  {
    super._beforeAuctionStarted(nftContract, tokenId);
  }
  function _transferFromEscrow(
    address nftContract,
    uint256 tokenId,
    address recipient,
    address authorizeSeller
  ) internal override(NFTMarketCore, NFTMarketReserveAuction, NFTMarketBuyPrice) {
    super._transferFromEscrow(nftContract, tokenId, recipient, authorizeSeller);
  }
  function _transferFromEscrowIfAvailable(
    address nftContract,
    uint256 tokenId,
    address recipient
  ) internal override(NFTMarketCore, NFTMarketReserveAuction, NFTMarketBuyPrice) {
    super._transferFromEscrowIfAvailable(nftContract, tokenId, recipient);
  }
  function _transferToEscrow(address nftContract, uint256 tokenId)
    internal
    override(NFTMarketCore, NFTMarketReserveAuction, NFTMarketBuyPrice)
  {
    super._transferToEscrow(nftContract, tokenId);
  }
  function _getSellerFor(address nftContract, uint256 tokenId)
    internal
    view
    override(NFTMarketCore, NFTMarketReserveAuction, NFTMarketBuyPrice)
    returns (address payable seller)
  {
    seller = super._getSellerFor(nftContract, tokenId);
  }
}