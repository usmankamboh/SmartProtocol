// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./a/ICollectionContractInitializer.sol";
import "./a/ICollectionFactory.sol";
import "./a/IProxyCall.sol";
import "./a/IRoles.sol";
import "./a/AddressUpgradeable.sol";
import "./a/Clones.sol";
import "./a//Strings.sol";
contract FNDCollectionFactory is ICollectionFactory {
  using AddressUpgradeable for address;
  using AddressUpgradeable for address payable;
  using Clones for address;
  using Strings for uint256;
  IRoles public rolesContract;
  address public implementation;
  IProxyCall public proxyCallContract;
  uint256 public version;
  event CollectionCreated(
    address indexed collectionContract,
    address indexed creator,
    uint256 indexed version,
    string name,
    string symbol,
    uint256 nonce
  );
  event ImplementationUpdated(address indexed implementation, uint256 indexed version);
  event ProxyCallContractUpdated(address indexed proxyCallContract);
  event RolesContractUpdated(address indexed rolesContract);

  modifier onlyAdmin() {
    require(rolesContract.isAdmin(msg.sender), "FNDCollectionFactory: Caller does not have the Admin role");
    _;
  }
  constructor(address _proxyCallContract, address _rolesContract) {
    _updateRolesContract(_rolesContract);
    _updateProxyCallContract(_proxyCallContract);
  }
  function adminUpdateImplementation(address _implementation) external onlyAdmin {
    _updateImplementation(_implementation);
  }
  function adminUpdateProxyCallContract(address _proxyCallContract) external onlyAdmin {
    _updateProxyCallContract(_proxyCallContract);
  }
  function adminUpdateRolesContract(address _rolesContract) external onlyAdmin {
    _updateRolesContract(_rolesContract);
  }
  function createCollection(
    string calldata name,
    string calldata symbol,
    uint256 nonce
  ) external returns (address collectionAddress) {
    require(bytes(symbol).length != 0, "FNDCollectionFactory: Symbol is required");

    // This reverts if the NFT was previously created using this implementation version + msg.sender + nonce
    collectionAddress = implementation.cloneDeterministic(_getSalt(msg.sender, nonce));

    ICollectionContractInitializer(collectionAddress).initialize(payable(msg.sender), name, symbol);

    emit CollectionCreated(collectionAddress, msg.sender, version, name, symbol, nonce);
  }

  function _updateRolesContract(address _rolesContract) private {
    require(_rolesContract.isContract(), "FNDCollectionFactory: RolesContract is not a contract");
    rolesContract = IRoles(_rolesContract);

    emit RolesContractUpdated(_rolesContract);
  }
  function _updateImplementation(address _implementation) private {
    require(_implementation.isContract(), "FNDCollectionFactory: Implementation is not a contract");
    implementation = _implementation;
    unchecked {
      // Version cannot overflow 256 bits.
      version++;
    }

    // The implementation is initialized when assigned so that others may not claim it as their own.
    ICollectionContractInitializer(_implementation).initialize(
      payable(address(rolesContract)),
      string(abi.encodePacked("Foundation Collection Template v", version.toString())),
      string(abi.encodePacked("FCTv", version.toString()))
    );

    emit ImplementationUpdated(_implementation, version);
  }

  function _updateProxyCallContract(address _proxyCallContract) private {
    require(_proxyCallContract.isContract(), "FNDCollectionFactory: Proxy call address is not a contract");
    proxyCallContract = IProxyCall(_proxyCallContract);

    emit ProxyCallContractUpdated(_proxyCallContract);
  }
  function predictCollectionAddress(address creator, uint256 nonce) external view returns (address collectionAddress) {
    collectionAddress = implementation.predictDeterministicAddress(_getSalt(creator, nonce));
  }

  function _getSalt(address creator, uint256 nonce) private pure returns (bytes32) {
    return keccak256(abi.encodePacked(creator, nonce));
  }
}