
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {UpgradeableModularAccount} from "../../account/UpgradeableModularAccount.sol";
import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction,
    ManifestExternalCallPermission
} from "../../interfaces/IPlugin.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {ISessionKeyPlugin} from "./interfaces/ISessionKeyPlugin.sol";
import {ISingleOwnerPlugin} from "../owner/ISingleOwnerPlugin.sol";
import {SingleOwnerPlugin} from "../owner/SingleOwnerPlugin.sol";

/// @title Session Key Plugin
/// @author Seungmin Jeon, Sang Kim
/// @notice This plugin allows an EOA or smart contract to own a modular account.
/// It also supports [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) signature
/// validation for both validating the signature on user operations and in
/// exposing its own `isValidSignature` method. This only works when the owner of
/// modular account also support ERC-1271.
///
/// ERC-4337's bundler validation rules limit the types of contracts that can be
/// used as owners to validate user operation signatures. For example, the
/// contract's `isValidSignature` function may not use any forbidden opcodes
/// such as `TIMESTAMP` or `NUMBER`, and the contract may not be an ERC-1967
/// proxy as it accesses a constant implementation slot not associated with
/// the account, violating storage access rules. This also means that the
/// owner of a modular account may not be another modular account if you want to
/// send user operations through a bundler.
contract BaseSessionKeyPlugin is BasePlugin, ISessionKeyPlugin {
    using ECDSA for bytes32;

    string public constant NAME = "Token Session Key Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Seungmin Jeon, Sang Kim";

    uint256 internal constant _DATE_LENGTH = 6;

    mapping(address => mapping(address => bytes)) internal _sessionDuration;

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function addTemporaryOwner(address tempOwner, uint48 _after, uint48 _until) external {
        if (_until <= _after) {
            revert WrongTimeRangeForSession();
        }
        bytes memory sessionDuration_ = abi.encodePacked(_after, _until);
        _sessionDuration[msg.sender][tempOwner] = sessionDuration_;
        emit TemporaryOwnerAdded(msg.sender, tempOwner, _after, _until);
    }

    /// @inheritdoc ISessionKeyPlugin
    function removeTemporaryOwner(address tempOwner) external {
        delete _sessionDuration[msg.sender][tempOwner];
        emit TemporaryOwnerRemoved(msg.sender, tempOwner);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin view functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ISessionKeyPlugin
    function getSessionDuration(address account, address tempOwner) external view returns (uint48 _after, uint48 _until) {
        (_after, _until) = _decode(_sessionDuration[account][tempOwner]);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function userOpValidationFunction(uint8 functionId, UserOperation calldata userOp, bytes32 userOpHash)
        external
        view
        override
        returns (uint256)
    {
        (address signer,) = (userOpHash.toEthSignedMessageHash()).tryRecover(userOp.signature);
        if (functionId == uint8(FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER)) {
            if (_sessionDuration[msg.sender][signer].length != 0) {
                (uint48 _after, uint48 _until) = _decode(_sessionDuration[msg.sender][signer]);
                return _packValidationData(true, _after, _until);
            }
        }
        revert NotImplemented();
    }

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        string[] memory ownerPermissions = new string[](1);
        ownerPermissions[0] = "Allow Temporary Ownership";

        manifest.executionFunctions = new ManifestExecutionFunction[](2);
        manifest.executionFunctions[0] =
            ManifestExecutionFunction(this.addTemporaryOwner.selector, ownerPermissions);
        manifest.executionFunctions[1] = ManifestExecutionFunction(this.removeTemporaryOwner.selector, new string[](0));

        ManifestFunction memory ownerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_OWNER),
            dependencyIndex: 1 
        });
        ManifestFunction memory tempOwnerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.SELF,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER),
            dependencyIndex: 0 // Unused.
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](3);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: UpgradeableModularAccount.executeFromPluginExternal.selector,
            associatedFunction: tempOwnerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.addTemporaryOwner.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[2] = ManifestAssociatedFunction({
            executionSelector: this.removeTemporaryOwner.selector,
            associatedFunction: ownerUserOpValidationFunction
        });
        

        ManifestFunction memory ownerOrSelfRuntimeValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: uint8(FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF),
            dependencyIndex: 1 
        });

        manifest.runtimeValidationFunctions = new ManifestAssociatedFunction[](5);
        manifest.runtimeValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.addTemporaryOwner.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });
        manifest.runtimeValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: this.removeTemporaryOwner.selector,
            associatedFunction: ownerOrSelfRuntimeValidationFunction
        });

        manifest.dependencyInterfaceIds = new bytes4[](2);
        manifest.dependencyInterfaceIds[0] = type(ISessionKeyPlugin).interfaceId;
        manifest.dependencyInterfaceIds[1] = type(ISingleOwnerPlugin).interfaceId;

        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ISessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Internal / Private functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    function _decode(bytes memory _data) internal pure returns (uint48 _after, uint48 _until) {
        assembly {
            _after := mload(add(_data, _DATE_LENGTH))
            _until := mload(add(_data, mul(_DATE_LENGTH, 2)))
        }
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }
}
