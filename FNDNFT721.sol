// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./a/ERC165.sol";
import "./a/Initializable.sol";
import "./a/ERC721Upgradeable.sol";
import "./a/FoundationTreasuryNode.sol";
import "./a/NFT721Core.sol";
import "./a/NFT721Market.sol";
import "./a/NFT721Creator.sol";
import "./a/NFT721Metadata.sol";
import "./a/NFT721Mint.sol";
import "./a/NFT721ProxyCall.sol";
import "./a/ERC165UpgradeableGap.sol";
contract FNDNFT721 is
  Initializable,
  FoundationTreasuryNode,
  ERC165UpgradeableGap,
  ERC165,
  OZERC721Upgradeable,
  NFT721Core,
  NFT721ProxyCall,
  NFT721Creator,
  NFT721Market,
  NFT721Metadata,
  NFT721Mint
{
  constructor(address payable treasury)
    FoundationTreasuryNode(treasury) // solhint-disable-next-line no-empty-blocks
  {}
  function initialize() external initializer {
    OZERC721Upgradeable.__ERC721_init();
    NFT721Mint._initializeNFT721Mint();
  }
  function adminUpdateConfig(
    address _nftMarket,
    string calldata baseURI,
    address proxyCallContract
  ) external onlyFoundationAdmin {
    _updateNFTMarket(_nftMarket);
    _updateBaseURI(baseURI);
    _updateProxyCall(proxyCallContract);
  }
  function _burn(uint256 tokenId) internal override(OZERC721Upgradeable, NFT721Creator, NFT721Metadata, NFT721Mint) {
    super._burn(tokenId);
  }

  function supportsInterface(bytes4 interfaceId)
    public
    view
    override(ERC165, NFT721Mint, OZERC721Upgradeable, NFT721Creator, NFT721Market)
    returns (bool)
  {
    return super.supportsInterface(interfaceId);
  }
}
