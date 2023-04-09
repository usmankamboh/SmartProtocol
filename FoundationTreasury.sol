// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;
import "./a/AdminRole.sol";
import "./a/OperatorRole.sol";
import "./a/CollateralManagement.sol";
contract FoundationTreasury is AdminRole, OperatorRole, CollateralManagement {
  function initialize(address admin) external initializer {
    AdminRole._initializeAdminRole(admin);
  }
}
