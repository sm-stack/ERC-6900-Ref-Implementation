// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import "forge-std/console.sol";

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
import {MockERC20} from "../mocks/MockERC20.sol";

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

    MockERC20 public mockERC20impl;
    MockERC20 public mockERC20;
    address public mockEmptyERC20Addr;

    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;

    address public owner;
    uint256 public ownerKey;

    address public maliciousOwner;
    uint256 public maliciousOwnerKey;

    address public tempOwner;
    uint256 public tempOwnerKey;

    address payable public beneficiary;

    ContractOwner public contractOwner;

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
        mockERC20impl = new MockERC20('Mock', 'MCK');

        // Etching MockERC20 code into hardcoded address at TokenSessionKeyPlugin
        mockEmptyERC20Addr = tokenSessionKeyPlugin.TARGET_ERC20_CONTRACT();
        bytes memory code = address(mockERC20impl).code;
        vm.etch(mockEmptyERC20Addr, code);
        mockERC20 = MockERC20(mockEmptyERC20Addr);

        (owner, ownerKey) = makeAddrAndKey("owner");
        (maliciousOwner, maliciousOwnerKey) = makeAddrAndKey("maliciousOwner");
        (tempOwner, tempOwnerKey) = makeAddrAndKey("tempOwner");

        beneficiary = payable(makeAddr("beneficiary"));
        vm.deal(beneficiary, 1 wei);
        vm.deal(owner, 10 ether);

        contractOwner = new ContractOwner();

        // Here, SingleOwnerPlugin already installed in factory
        account = factory.createAccount(owner, 0);

        // Mine Mock ERC20 Tokens to account
        mockERC20.mint(address(account), 1 ether);
        // Fund the account with some ether
        vm.deal(address(account), 1 ether);

        vm.startPrank(owner);
        FunctionReference[] memory baseSessionDependency = new FunctionReference[](2);
        baseSessionDependency[0] = address(ownerPlugin).pack(
            uint8(ISingleOwnerPlugin.FunctionId.USER_OP_VALIDATION_OWNER)
        );
        baseSessionDependency[1] = address(ownerPlugin).pack(
            uint8(ISingleOwnerPlugin.FunctionId.RUNTIME_VALIDATION_OWNER_OR_SELF)
        );

        bytes32 baseSessionKeyManifestHash = keccak256(abi.encode(baseSessionKeyPlugin.pluginManifest()));

        account.installPlugin({
            plugin: address(baseSessionKeyPlugin),
            manifestHash: baseSessionKeyManifestHash,
            pluginInitData: "",
            dependencies: baseSessionDependency,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });

        FunctionReference[] memory tokenSessionDependency = new FunctionReference[](1);
        tokenSessionDependency[0] = address(baseSessionKeyPlugin).pack(
            uint8(ISessionKeyPlugin.FunctionId.USER_OP_VALIDATION_TEMPORARY_OWNER)
        );
        bytes32 tokenSessionKeyManifestHash =
            keccak256(abi.encode(tokenSessionKeyPlugin.pluginManifest()));
        account.installPlugin({
            plugin: address(tokenSessionKeyPlugin),
            manifestHash: tokenSessionKeyManifestHash,
            pluginInitData: "",
            dependencies: tokenSessionDependency,
            injectedHooks: new IPluginManager.InjectedHook[](0)
        });
        vm.stopPrank();
        vm.startPrank(address(account));
        baseSessionKeyPlugin.addTemporaryOwner(tempOwner, 0, type(uint48).max);
        (uint48 _after, uint48 _until) = 
            baseSessionKeyPlugin.getSessionDuration(address(account), tempOwner);
        assertEq(_after, 0);
        assertEq(_until, type(uint48).max);
    }

    function test_transferByTempOwner() public {
        // Calldata for transferFrom
        bytes[] memory callData = new bytes[](2);
        callData[0] = abi.encodeWithSelector(
            tokenSessionKeyPlugin.APPROVE_SELECTOR(),
            address(account),
            1 ether
        );
        callData[1] = abi.encodeWithSelector(
            tokenSessionKeyPlugin.TRANSFERFROM_SELECTOR(),
            address(account),
            beneficiary,
            1 ether
        );

        UserOperation[] memory userOps = new UserOperation[](2);

        for (uint i; i < callData.length;) {
            bytes memory userOpCallData = abi.encodeCall(
                TokenSessionKeyPlugin.routeCallToExecuteFromPluginExternal,
                (address(mockERC20), callData[i])
            );
            UserOperation memory userOp = UserOperation({
                sender: address(account),
                nonce: i,
                initCode: '',
                callData: userOpCallData,
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
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(tempOwnerKey, userOpHash.toEthSignedMessageHash());
            userOp.signature = abi.encodePacked(r, s, v);
            
            userOps[i] = userOp;

            unchecked {
                i++;
            }
        }
        entryPoint.handleOps(userOps, beneficiary);

        assertEq(mockERC20.balanceOf(address(account)), 0);
        assertEq(mockERC20.balanceOf(beneficiary), 1 ether);
    }
}

