

// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction,
    ManifestExternalCallPermission
} from "../../interfaces/IPlugin.sol";
import {BasePlugin} from "../BasePlugin.sol";
import {BaseSessionKeyPlugin} from "./BaseSessionKeyPlugin.sol";
import {ITokenSessionKeyPlugin} from "./interfaces/ITokenSessionKeyPlugin.sol";
import {ISessionKeyPlugin} from "./interfaces/ISessionKeyPlugin.sol";
import {IPluginExecutor} from "../../interfaces/IPluginExecutor.sol";

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
contract TokenSessionKeyPlugin is BasePlugin, ITokenSessionKeyPlugin {

    string public constant NAME = "Base Session Key Plugin";
    string public constant VERSION = "1.0.0";
    string public constant AUTHOR = "Seungmin Jeon, Sang Kim";

    address internal constant _TARGET_ERC20_CONTRACT = 0xdeaDDeADDEaDdeaDdEAddEADDEAdDeadDEADDEaD;
    bytes4 internal constant _TRANSFERFROM_SELECTOR = bytes4(keccak256(bytes("transferFrom(address,address,uint256)")));
    bytes4 internal constant _APPROVE_SELECTOR = bytes4(keccak256(bytes("approve(address,uint256)")));

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Execution functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

    /// @inheritdoc ITokenSessionKeyPlugin
    function routeCallToExecuteFromPluginExternal(
        address account,
        address target,
        bytes memory data    
    ) external returns (bytes memory returnData) {
        require(msg.sender == account, "Only callable from this plugin");
        returnData = IPluginExecutor(account).executeFromPluginExternal(target, 0, data);
    }

    // ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    // ┃    Plugin interface functions    ┃
    // ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    
    /// @inheritdoc BasePlugin
    function onInstall(bytes calldata data) external override {}

    /// @inheritdoc BasePlugin
    function onUninstall(bytes calldata) external override {}

    /// @inheritdoc BasePlugin
    function pluginManifest() external pure override returns (PluginManifest memory) {
        PluginManifest memory manifest;

        manifest.name = NAME;
        manifest.version = VERSION;
        manifest.author = AUTHOR;

        string[] memory ownerPermissions = new string[](1);
        ownerPermissions[0] = "Allow Token Operation By Session Key";

        manifest.executionFunctions = new ManifestExecutionFunction[](1);
        manifest.executionFunctions[0] = ManifestExecutionFunction(this.routeCallToExecuteFromPluginExternal.selector, ownerPermissions);

        ManifestFunction memory tempOwnerUserOpValidationFunction = ManifestFunction({
            functionType: ManifestAssociatedFunctionType.DEPENDENCY,
            functionId: uint8(FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER),
            dependencyIndex: 0 // Used as first index
        });
        manifest.userOpValidationFunctions = new ManifestAssociatedFunction[](2);
        manifest.userOpValidationFunctions[0] = ManifestAssociatedFunction({
            executionSelector: this.routeCallToExecuteFromPluginExternal.selector,
            associatedFunction: tempOwnerUserOpValidationFunction
        });
        manifest.userOpValidationFunctions[1] = ManifestAssociatedFunction({
            executionSelector: BaseSessionKeyPlugin.userOpValidationFunction.selector,
            associatedFunction: tempOwnerUserOpValidationFunction
        });

        manifest.dependencyInterfaceIds = new bytes4[](1);
        manifest.dependencyInterfaceIds[0] = type(ISessionKeyPlugin).interfaceId;

        bytes4[] memory permittedExecutionSelectors = new bytes4[](2);
        permittedExecutionSelectors[0] = _TRANSFERFROM_SELECTOR;
        permittedExecutionSelectors[1] = _APPROVE_SELECTOR;

        manifest.permittedExternalCalls = new ManifestExternalCallPermission[](1);
        manifest.permittedExternalCalls[0] = ManifestExternalCallPermission({
            externalAddress: _TARGET_ERC20_CONTRACT,
            permitAnySelector: false,
            selectors: permittedExecutionSelectors
        });

        return manifest;
    }

    // ┏━━━━━━━━━━━━━━━┓
    // ┃    EIP-165    ┃
    // ┗━━━━━━━━━━━━━━━┛

    /// @inheritdoc BasePlugin
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(ITokenSessionKeyPlugin).interfaceId || super.supportsInterface(interfaceId);
    }
}
