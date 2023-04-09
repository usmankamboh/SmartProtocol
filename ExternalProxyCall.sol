// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./a/AddressUpgradeable.sol";
import "./a/IProxyCall.sol";
contract ExternalProxyCall is IProxyCall {
  using AddressUpgradeable for address;

  function proxyCallAndReturnAddress(address externalContract, bytes memory callData)
    external
    override
    returns (address payable result)
  {
    bytes memory returnData = externalContract.functionCall(callData);

    // Skip the length at the start of the bytes array and return the data, casted to an address
    // solhint-disable-next-line no-inline-assembly
    assembly {
      result := mload(add(returnData, 32))
    }
  }
}