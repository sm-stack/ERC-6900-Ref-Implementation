// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";

import {EntryPoint} from "@eth-infinitism/account-abstraction/core/EntryPoint.sol";
import {UserOperation} from "@eth-infinitism/account-abstraction/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {SingleOwnerPlugin} from "../../src/plugins/owner/SingleOwnerPlugin.sol";
import {ISingleOwnerPlugin} from "../../src/plugins/owner/ISingleOwnerPlugin.sol";
import {BaseSessionKeyPlugin} from "../../src/plugins/session-key/BaseSessionKeyPlugin.sol";
import {ISessionKeyPlugin} from "../../src/plugins/session-key/interfaces/ISessionKeyPlugin.sol";
import {TokenSessionKeyPlugin} from "../../src/plugins/session-key/TokenSessionKeyPlugin.sol";
import {ITokenSessionKeyPlugin} from "../../src/plugins/session-key/interfaces/ITokenSessionKeyPlugin.sol";
import {ContractOwner} from "../mocks/ContractOwner.sol";

import {UpgradeableModularAccount} from "../../src/account/UpgradeableModularAccount.sol";
import {MSCAFactoryFixture} from "../mocks/MSCAFactoryFixture.sol";
import {FunctionReference, FunctionReferenceLib} from "../../src/libraries/FunctionReferenceLib.sol";
import {IPluginManager} from "../../src/interfaces/IPluginManager.sol";

import {
    ManifestFunction,
    ManifestAssociatedFunctionType,
    ManifestAssociatedFunction,
    PluginManifest,
    ManifestExecutionFunction,
    ManifestExternalCallPermission
} from "../../src/interfaces/IPlugin.sol";


contract SessionKeyPluginTest is Test {
    using ECDSA for bytes32;
    using FunctionReferenceLib for address;

    SingleOwnerPlugin public ownerPlugin;
    BaseSessionKeyPlugin public baseSessionKeyPlugin;
    TokenSessionKeyPlugin public tokenSessionKeyPlugin;
    EntryPoint public entryPoint;
    MSCAFactoryFixture public factory;
    UpgradeableModularAccount public account;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    address public owner;
    uint256 public ownerKey;

    address public maliciousOwner;
    uint256 public maliciousOwnerKey;

    address public tempOwner;
    uint256 public tempOwnerKey;

    address payable public beneficiary;

    ContractOwner public contractOwner;

    address public mockERC20 = 0x00adDEADDEAddeaDDEAddEaDDEaDDeadDEadDEaD;

    uint256 public constant CALL_GAS_LIMIT = 50000;
    uint256 public constant VERIFICATION_GAS_LIMIT = 1200000;

    // Event declarations (needed for vm.expectEmit)
    event OwnershipTransferred(address indexed account, address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        ownerPlugin = new SingleOwnerPlugin();
        baseSessionKeyPlugin = new BaseSessionKeyPlugin();
        tokenSessionKeyPlugin = new TokenSessionKeyPlugin();

        entryPoint = new EntryPoint();
        factory = new MSCAFactoryFixture(entryPoint, ownerPlugin);

        (owner, ownerKey) = makeAddrAndKey("owner");
        (maliciousOwner, maliciousOwnerKey) = makeAddrAndKey("maliciousOwner");
        (tempOwner, tempOwnerKey) = makeAddrAndKey("tempOwner");

        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);
        vm.deal(address(this), 10 ether);

        contractOwner = new ContractOwner();

        // Here, SingleOwnerPlugin already installed in factory
        account = factory.createAccount(owner, 0);
        
        // First element should be empty
        FunctionReference[] memory baseSessionDependency = new FunctionReference[](2);
        baseSessionDependency[0] = address(baseSessionKeyPlugin).pack(
            uint8(ManifestAssociatedFunctionType.SELF)
        );
        baseSessionDependency[1] = address(ownerPlugin).pack(
            uint8(ManifestAssociatedFunctionType.DEPENDENCY)
        );

        bytes32 baseSessionKeyManifestHash = keccak256(abi.encode(baseSessionKeyPlugin.pluginManifest()));
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: '',
            callData: abi.encodeCall(UpgradeableModularAccount.installPlugin, (
                address(baseSessionKeyPlugin), 
                baseSessionKeyManifestHash, 
                "", 
                baseSessionDependency, 
                new IPluginManager.InjectedHook[](0)
            )),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
        
        // account.installPlugin({
        //     plugin: address(baseSessionKeyPlugin),
        //     manifestHash: baseSessionKeyManifestHash,
        //     pluginInitData: "",
        //     dependencies: baseSessionDependency,
        //     injectedHooks: new IPluginManager.InjectedHook[](0)
        // });

        // // First element should be empty
        // FunctionReference[] memory tokenSessionDependency = new FunctionReference[](2);
        // tokenSessionDependency[1] = address(tokenSessionKeyPlugin).pack(
        //     uint8(ManifestAssociatedFunctionType.DEPENDENCY)
        // );
        // bytes32 tokenSessionKeyManifestHash =
        //     keccak256(abi.encode(tokenSessionKeyPlugin.pluginManifest()));
        // account.installPlugin({
        //     plugin: address(tokenSessionKeyPlugin),
        //     manifestHash: tokenSessionKeyManifestHash,
        //     pluginInitData: "",
        //     dependencies: tokenSessionDependency,
        //     injectedHooks: new IPluginManager.InjectedHook[](0)
        // });
    }

    function test_basicUserOp() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: '',
            callData: abi.encodeCall(BaseSessionKeyPlugin.addTemporaryOwner, (tempOwner, 0, 1000)),
            callGasLimit: CALL_GAS_LIMIT,
            verificationGasLimit: VERIFICATION_GAS_LIMIT,
            preVerificationGas: 0,
            maxFeePerGas: 2,
            maxPriorityFeePerGas: 1,
            paymasterAndData: "",
            signature: ""
        });

        // Generate signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, userOpHash.toEthSignedMessageHash());
        userOp.signature = abi.encodePacked(r, s, v);

        UserOperation[] memory userOps = new UserOperation[](1);
        userOps[0] = userOp;

        entryPoint.handleOps(userOps, beneficiary);
    }

    
}

