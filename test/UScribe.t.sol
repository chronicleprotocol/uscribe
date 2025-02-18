// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {LibValidator, Validator} from "../script/libs/LibValidator.sol";

import {IUScribe} from "../src/IUScribe.sol";
import {UScribe} from "../src/UScribe.sol";
import {UPokeData, SchnorrData, ECDSAData} from "../src/Types.sol";
import {LibSecp256k1} from "../src/libs/LibSecp256k1.sol";

import {DummyConsumer} from "./DummyConsumer.sol";

contract UScribeTest is Test {
    using LibValidator for Validator;
    using LibValidator for Validator[];

    DummyConsumer uscribe;

    // Events copied from UScribe.
    event UPoked(address indexed caller, string proofURI);
    event ValidatorLiftedSchnorr(
        address indexed caller, address indexed validator
    );
    event ValidatorDroppedSchnorr(
        address indexed caller, address indexed validator
    );
    event BarUpdatedSchnorr(address indexed caller, uint8 oldBar, uint8 newBar);
    event ValidatorLiftedECDSA(
        address indexed caller, address indexed validator
    );
    event ValidatorDroppedECDSA(
        address indexed caller, address indexed validator
    );
    event BarUpdatedECDSA(address indexed caller, uint8 oldBar, uint8 newBar);

    // Events copied from Consumer.
    event Poked(bytes payload);

    function setUp() public {
        uscribe = new DummyConsumer(address(this), bytes32("VA::TBILL"));
    }

    //--------------------------------------------------------------------------
    // Setup Functions

    //----------------------------------
    // UPokeData

    struct UPokeDataSeed {
        bytes payload;
        string proofURI;
    }

    function constructUPokeData(UPokeDataSeed calldata seed)
        internal
        pure
        returns (UPokeData memory)
    {
        // Create payload with length in [0, 1000].
        bytes memory payload;
        if (seed.payload.length == 0) {
            payload = hex"FF";
        } else if (seed.payload.length > 1000) {
            payload = abi.encodePacked(keccak256(seed.payload));
        } else {
            payload = seed.payload;
        }

        // Create proofURI with length in [0, 1000].
        string memory proofURI;
        if (bytes(seed.proofURI).length == 0) {
            proofURI = "ipfs://chronicle";
        } else if (bytes(seed.proofURI).length > 1000) {
            proofURI = string(abi.encodePacked(keccak256(bytes(seed.proofURI))));
        } else {
            proofURI = seed.proofURI;
        }

        // Return bounded uPokeData.
        return UPokeData(payload, proofURI);
    }

    //----------------------------------
    // SchnorrStorage

    struct SchnorrStorageSeed {
        uint bloom;
        uint bar;
    }

    function setUpSchnorrStorage(SchnorrStorageSeed calldata seed)
        internal
        returns (Validator[] memory)
    {
        // Construct non-zero bloom.
        uint bloom = _bound(seed.bloom, 1, type(uint).max);

        // Construct validator list from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct bar in [1, validators.length].
        uint8 bar = uint8(_bound(seed.bar, 1, validators.length));
        vm.assume(bar != 0);

        // Construct list of validators' public keys.
        LibSecp256k1.Point[] memory pubKeys =
            new LibSecp256k1.Point[](validators.length);
        for (uint i; i < pubKeys.length; i++) {
            pubKeys[i] = validators[i].toPublicKey();
        }

        // Lift validators.
        uscribe.liftSchnorr(pubKeys);

        // Set bar.
        uscribe.setBarSchnorr(bar);

        // Return list of lifted validators.
        return validators;
    }

    //----------------------------------
    // ECDSAStorage

    struct ECDSAStorageSeed {
        uint bloom;
        uint bar;
    }

    function setUpECDSAStorage(ECDSAStorageSeed calldata seed)
        internal
        returns (Validator[] memory)
    {
        // Construct non-zero bloom.
        uint bloom = _bound(seed.bloom, 1, type(uint).max);

        // Construct validator list from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct bar in [1, validators.length].
        uint8 bar = uint8(_bound(seed.bar, 1, validators.length));
        vm.assume(bar != 0);

        // Construct list of validators' addresses.
        address[] memory addrs = new address[](validators.length);
        for (uint i; i < addrs.length; i++) {
            addrs[i] = validators[i].toAddress();
        }

        // Lift validators.
        uscribe.liftECDSA(addrs);

        // Set bar.
        uscribe.setBarECDSA(bar);

        // Return list of lifted validators.
        return validators;
    }

    //--------------------------------------------------------------------------
    // Test: Deployment

    function test_Deployment() public view {
        // Only address given during construction is auth'ed.
        assertTrue(uscribe.authed(address(this)));
        assertEq(uscribe.authed().length, 1);

        // Wat given during construction is set.
        assertEq(uscribe.wat(), bytes32("VA::TBILL"));

        // Bars are set to 255.
        assertEq(uscribe.barSchnorr(), 255);
        assertEq(uscribe.barECDSA(), 255);

        // No validators lifted for Schnorr or ECDSA.
        assertEq(uscribe.validatorsSchnorr().length, 0);
        assertEq(uscribe.validatorsECDSA().length, 0);
    }

    function test_Deployment_FailsIf_WatIsZero() public {
        vm.expectRevert();
        new DummyConsumer(address(this), bytes32(""));
    }

    //--------------------------------------------------------------------------
    // Test: Poke Functionality

    //----------------------------------
    // Schnorr

    function testFuzz_pokeSchnorr(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed
    ) public {
        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select bar-sized subset of validators.
        uint8 bar = uscribe.barSchnorr();
        assembly ("memory-safe") {
            mstore(validators, bar)
        }

        // Create Schnorr musig with bar participants from lifted validators.
        SchnorrData memory schnorr = validators.signSchnorr(message);

        // Expect general UScribe event.
        vm.expectEmit();
        emit UPoked(address(this), uPokeData.proofURI);

        // Expect app-specific Consumer event.
        vm.expectEmit();
        emit Poked(uPokeData.payload);

        // Poke uPokeData with Schnorr musig.
        uscribe.poke(uPokeData, schnorr);
    }

    function testFuzz_pokeSchnorr_FailsIf_VerificationFailed_DueTo_BarNotReached(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed,
        uint numSignersSeed
    ) public {
        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select number of signers less than bar.
        uint numSigners = _bound(numSignersSeed, 0, uscribe.barSchnorr() - 1);

        // Select numSigners-sized subset of validators.
        assembly ("memory-safe") {
            mstore(validators, numSigners)
        }

        // Create Schnorr musig with numSigners participants from lifted validators.
        SchnorrData memory schnorr;
        if (validators.length != 0) {
            schnorr = validators.signSchnorr(message);
        }

        // Expect poke of uPokeData with Schnorr musig to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_BarNotReached.selector
            )
        );
        uscribe.poke(uPokeData, schnorr);
    }

    function testFuzz_pokeSchnorr_FailsIf_VerificationFailed_DueTo_SignatureInvalid(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed,
        uint signatureMask,
        uint160 commitmentMask
    ) public {
        vm.assume(signatureMask != 0 || commitmentMask != 0);

        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select bar-sized subset of validators.
        uint8 bar = uscribe.barSchnorr();
        assembly ("memory-safe") {
            mstore(validators, bar)
        }

        // Create Schnorr musig with bar participants from lifted validators.
        SchnorrData memory schnorr = validators.signSchnorr(message);

        // Mutate Schnorr musig.
        schnorr.signature = bytes32(uint(schnorr.signature) ^ signatureMask);
        schnorr.commitment =
            address(uint160(schnorr.commitment) ^ commitmentMask);

        // Expect poke of uPokeData with Schnorr musig to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_SignatureInvalid.selector
            )
        );
        uscribe.poke(uPokeData, schnorr);
    }

    function testFuzz_pokeSchnorr_FailsIf_VerificationFailed_DueTo_ValidatorInvalid(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed,
        uint validatorIdsIndexSeed
    ) public {
        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);
        vm.assume(validators.length != 256);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select bar-sized subset of validators.
        uint8 bar = uscribe.barSchnorr();
        assembly ("memory-safe") {
            mstore(validators, bar)
        }

        // Create Schnorr musig with bar participants from lifted validators.
        SchnorrData memory schnorr = validators.signSchnorr(message);

        // Find validator id not lifted.
        uint8 nonLiftedId;
        for (uint i; i < 256; i++) {
            (bool lifted,) = uscribe.validatorsSchnorr(uint8(i));
            if (!lifted) {
                nonLiftedId = uint8(i);
                break;
            }
        }

        // Set non-lifted id as signer at random point in validatorIds blob.
        uint validatorIdsIndex = _bound(validatorIdsIndexSeed, 0, bar - 1);
        schnorr.validatorIds[validatorIdsIndex] = bytes1(nonLiftedId);

        // Expect poke of uPokeData with Schnorr musig to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_ValidatorInvalid.selector
            )
        );
        uscribe.poke(uPokeData, schnorr);
    }

    function testFuzz_pokeSchnorr_FailsIf_VerificationFailed_DueTo_DoubleSigningAttempted(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed,
        uint validatorIdsIndexSeed
    ) public {
        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);

        // Note that a bar of at least 2 is necessary.
        vm.assume(uscribe.barSchnorr() >= 2);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select bar-sized subset of validators.
        uint8 bar = uscribe.barSchnorr();
        assembly ("memory-safe") {
            mstore(validators, bar)
        }

        // Create Schnorr musig with bar participants from lifted validators.
        SchnorrData memory schnorr = validators.signSchnorr(message);

        // Duplicate random validator id at index 0.
        uint validatorIdsIndex =
            _bound(validatorIdsIndexSeed, 1, validators.length - 1);
        schnorr.validatorIds[0] = schnorr.validatorIds[validatorIdsIndex];

        // Expect poke of uPokeData with Schnorr musig to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_DoubleSigningAttempted.selector
            )
        );
        uscribe.poke(uPokeData, schnorr);
    }

    function testFuzz_pokeSchnorr_FailsIf_ConsumerRejectedPayload(
        UPokeDataSeed calldata uPokeDataSeed,
        SchnorrStorageSeed calldata schnorrStorageSeed
    ) public {
        // Setup Schnorr storage.
        Validator[] memory validators = setUpSchnorrStorage(schnorrStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        bytes32 message = uscribe.constructChronicleSignedMessage(
            bytes32("SCHNORR"), uPokeData
        );

        // Select bar-sized subset of validators.
        uint8 bar = uscribe.barSchnorr();
        assembly ("memory-safe") {
            mstore(validators, bar)
        }

        // Create Schnorr musig with bar participants from lifted validators.
        SchnorrData memory schnorr = validators.signSchnorr(message);

        // Let consumer reject payload.
        uscribe.setRejectPokes(true);

        // Expect poke to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_ConsumerRejectedPayload.selector,
                bytes4(0xFFFFFFFF)
            )
        );
        uscribe.poke(uPokeData, schnorr);
    }

    //----------------------------------
    // ECDSA

    function testFuzz_pokeECDSA(
        UPokeDataSeed calldata uPokeDataSeed,
        ECDSAStorageSeed calldata ecdsaStorageSeed
    ) public {
        // Setup ECDSA storage.
        Validator[] memory validators = setUpECDSAStorage(ecdsaStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(bytes32("ECDSA"), uPokeData);

        // Create bar ECDSA signatures from lifted validators.
        uint8 bar = uscribe.barECDSA();
        ECDSAData[] memory ecdsas = new ECDSAData[](bar);
        for (uint i; i < bar; i++) {
            ecdsas[i] = validators[i].signECDSA(message);
        }

        // Expect general UScribe event.
        vm.expectEmit();
        emit UPoked(address(this), uPokeData.proofURI);

        // Expect app-specific Consumer event.
        vm.expectEmit();
        emit Poked(uPokeData.payload);

        // Poke uPokeData with list of ECDSA signatures.
        uscribe.poke(uPokeData, ecdsas);
    }

    function testFuzz_pokeECDSA_FailsIf_VerificationFailed_DueTo_BarNotReached(
        UPokeDataSeed calldata uPokeDataSeed,
        ECDSAStorageSeed calldata ecdsaStorageSeed,
        uint numSignersSeed
    ) public {
        // Setup ECDSA storage.
        Validator[] memory validators = setUpECDSAStorage(ecdsaStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(bytes32("ECDSA"), uPokeData);

        // Select number of signers less than bar.
        uint numSigners = _bound(numSignersSeed, 0, uscribe.barECDSA() - 1);

        // Create numSigners ECDSA signatures from lifted validators.
        ECDSAData[] memory ecdsas = new ECDSAData[](numSigners);
        for (uint i; i < numSigners; i++) {
            ecdsas[i] = validators[i].signECDSA(message);
        }

        // Expect poke of uPokeData with list of ECDSA signatures to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_BarNotReached.selector
            )
        );
        uscribe.poke(uPokeData, ecdsas);
    }

    function testFuzz_pokeECDSA_FailsIf_VerificationFailed_DueTo_SignatureInvalid(
        UPokeDataSeed calldata uPokeDataSeed,
        ECDSAStorageSeed calldata ecdsaStorageSeed,
        uint ecdsaIndexSeed,
        uint rMask,
        uint sMask
    ) public {
        vm.assume(rMask != 0 || sMask != 0);

        // Setup ECDSA storage.
        Validator[] memory validators = setUpECDSAStorage(ecdsaStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(bytes32("ECDSA"), uPokeData);

        // Create bar ECDSA signatures from lifted validators.
        uint8 bar = uscribe.barECDSA();
        ECDSAData[] memory ecdsas = new ECDSAData[](bar);
        for (uint i; i < bar; i++) {
            ecdsas[i] = validators[i].signECDSA(message);
        }

        // Mutate random ECDSA signature.
        uint ecdsaIndex = _bound(ecdsaIndexSeed, 0, ecdsas.length - 1);
        ecdsas[ecdsaIndex].r = bytes32(uint(ecdsas[ecdsaIndex].r) ^ rMask);
        ecdsas[ecdsaIndex].s = bytes32(uint(ecdsas[ecdsaIndex].s) ^ sMask);

        // Expect poke of uPokeData with list of ECDSA signatures to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_SignatureInvalid.selector
            )
        );
        uscribe.poke(uPokeData, ecdsas);
    }

    function testFuzz_pokeECDSA_FailsIf_VerificationFailed_DueTo_DoubleSigningAttempted(
        UPokeDataSeed calldata uPokeDataSeed,
        ECDSAStorageSeed calldata ecdsaStorageSeed,
        uint ecdsaIndexSeed
    ) public {
        // Setup ECDSA storage.
        Validator[] memory validators = setUpECDSAStorage(ecdsaStorageSeed);

        // Note that a bar of at least 2 is necessary.
        vm.assume(uscribe.barECDSA() >= 2);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(bytes32("ECDSA"), uPokeData);

        // Create bar ECDSA signatures from lifted validators.
        uint8 bar = uscribe.barECDSA();
        ECDSAData[] memory ecdsas = new ECDSAData[](bar);
        for (uint i; i < bar; i++) {
            ecdsas[i] = validators[i].signECDSA(message);
        }

        // Duplicate random ECDSA signature at index 0.
        uint ecdsaIndex = _bound(ecdsaIndexSeed, 1, ecdsas.length - 1);
        ecdsas[0] = ecdsas[ecdsaIndex];

        // Expect poke of uPokeData with list of ECDSA signatures to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_VerificationFailed.selector,
                IUScribe.VerificationError_DoubleSigningAttempted.selector
            )
        );
        uscribe.poke(uPokeData, ecdsas);
    }

    function testFuzz_pokeECDSA_FailsIf_ConsumerRejectedPayload(
        UPokeDataSeed calldata uPokeDataSeed,
        ECDSAStorageSeed calldata ecdsaStorageSeed
    ) public {
        // Setup ECDSA storage.
        Validator[] memory validators = setUpECDSAStorage(ecdsaStorageSeed);

        // Construct uPokeData.
        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(bytes32("ECDSA"), uPokeData);

        // Create bar ECDSA signatures from lifted validators.
        uint8 bar = uscribe.barECDSA();
        ECDSAData[] memory ecdsas = new ECDSAData[](bar);
        for (uint i; i < bar; i++) {
            ecdsas[i] = validators[i].signECDSA(message);
        }

        // Let consumer reject payload.
        uscribe.setRejectPokes(true);

        // Expect poke to fail.
        vm.expectRevert(
            abi.encodeWithSelector(
                IUScribe.PokeError_ConsumerRejectedPayload.selector,
                bytes4(0xFFFFFFFF)
            )
        );
        uscribe.poke(uPokeData, ecdsas);
    }

    //--------------------------------------------------------------------------
    // Test: Chronicle Signed Message Functionality

    function testFuzz_constructChronicleSignedMessage_DerivesMessageFromWholeInput(
        bytes32 scheme,
        UPokeDataSeed calldata uPokeDataSeed,
        uint mask
    ) public view {
        vm.assume(mask != 0);

        UPokeData memory uPokeData = constructUPokeData(uPokeDataSeed);

        // Construct Chronicle Signed Message.
        bytes32 message =
            uscribe.constructChronicleSignedMessage(scheme, uPokeData);

        // Verify message differs if scheme mutated.
        bytes32 schemeMutated = bytes32(uint(scheme) ^ mask);
        assertNotEq(
            message,
            uscribe.constructChronicleSignedMessage(schemeMutated, uPokeData)
        );

        // Verify message differs if uPokeData.payload mutated.
        bytes memory payloadMutated = abi.encodePacked(uPokeData.payload, mask);
        assertNotEq(
            message,
            uscribe.constructChronicleSignedMessage(
                scheme, UPokeData(payloadMutated, uPokeData.proofURI)
            )
        );

        // Verify message differs if uPokeData.proofURI mutated.
        string memory proofURIMutated = string.concat(uPokeData.proofURI, ".");
        assertNotEq(
            message,
            uscribe.constructChronicleSignedMessage(
                scheme, UPokeData(uPokeData.payload, proofURIMutated)
            )
        );
    }

    //--------------------------------------------------------------------------
    // Test: Auth Protected Functions

    //----------------------------------
    // SchnorrStorage

    function testFuzz_liftSchnorr(uint bloom) public {
        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct list of validators' public keys.
        LibSecp256k1.Point[] memory pubKeys =
            new LibSecp256k1.Point[](validators.length);
        for (uint i; i < pubKeys.length; i++) {
            pubKeys[i] = validators[i].toPublicKey();
        }

        // Expect an event for each validator being lifted.
        for (uint i; i < validators.length; i++) {
            vm.expectEmit();
            emit ValidatorLiftedSchnorr(
                address(this), validators[i].toAddress()
            );
        }

        // Lift validators.
        uscribe.liftSchnorr(pubKeys);

        // Lifting is idempotent.
        uscribe.liftSchnorr(pubKeys);

        // Verify exactly expected validators got lifted.
        assertEq(uscribe.validatorsSchnorr().length, validators.length);
        for (uint i; i < validators.length; i++) {
            assertTrue(uscribe.validatorsSchnorr(validators[i].toAddress()));
        }
    }

    function testFuzz_liftSchnorr_FailsIf_PublicKeyIsZeroPoint(
        uint bloom,
        uint indexSeed
    ) public {
        vm.assume(bloom != 0);

        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Select random index.
        uint index = _bound(indexSeed, 0, validators.length - 1);

        // Construct list of validators' public keys.
        LibSecp256k1.Point[] memory pubKeys =
            new LibSecp256k1.Point[](validators.length);
        for (uint i; i < pubKeys.length; i++) {
            pubKeys[i] = validators[i].toPublicKey();
        }

        // Substitute public key at index by zero point.
        pubKeys[index] = LibSecp256k1.ZERO_POINT();

        // Expect lift to fail.
        vm.expectRevert();
        uscribe.liftSchnorr(pubKeys);
    }

    function test_liftSchnorr_FailsIf_IdAlreadyLifted() public {
        // Create two validators with same id.
        Validator memory v1 = LibValidator.newValidator(22171);
        Validator memory v2 = LibValidator.newValidator(38091);
        assert(v1.toId() == v2.toId());

        LibSecp256k1.Point[] memory pubKeys = new LibSecp256k1.Point[](1);

        pubKeys[0] = v1.toPublicKey();
        uscribe.liftSchnorr(pubKeys);

        pubKeys[0] = v2.toPublicKey();
        vm.expectRevert();
        uscribe.liftSchnorr(pubKeys);
    }

    function testFuzz_dropSchnorr(uint bloom) public {
        // Lift all 256 validators.
        Validator[] memory allValidators =
            LibValidator.newValidatorsFromBloom(type(uint).max);
        LibSecp256k1.Point[] memory allPubKeys =
            new LibSecp256k1.Point[](allValidators.length);
        for (uint i; i < allPubKeys.length; i++) {
            allPubKeys[i] = allValidators[i].toPublicKey();
        }
        uscribe.liftSchnorr(allPubKeys);

        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct list of validators' ids.
        uint8[] memory ids = new uint8[](validators.length);
        for (uint i; i < ids.length; i++) {
            ids[i] = validators[i].toId();
        }

        // Expect an event for each validator being dropped.
        for (uint i; i < ids.length; i++) {
            vm.expectEmit();
            emit ValidatorDroppedSchnorr(
                address(this), validators[i].toAddress()
            );
        }

        // Drop validators.
        uscribe.dropSchnorr(ids);

        // Verify exactly expected validators got dropped.
        assertEq(uscribe.validatorsSchnorr().length, 256 - validators.length);
        for (uint i; i < 256; i++) {
            (bool lifted,) = uscribe.validatorsSchnorr(uint8(i));
            assertEq(lifted, bloom & (1 << i) == 0);
        }
    }

    function testFuzz_setBarSchnorr(uint8 bar) public {
        vm.assume(bar != 0);

        // Only expect event if bar actually updated.
        if (uscribe.barSchnorr() != bar) {
            vm.expectEmit();
            emit BarUpdatedSchnorr(address(this), uscribe.barSchnorr(), bar);
        }

        // Update bar.
        uscribe.setBarSchnorr(bar);

        // Verify bar updated.
        assertEq(uscribe.barSchnorr(), bar);
    }

    function test_setBarSchnorr_FailsIf_BarIsZero() public {
        vm.expectRevert();
        uscribe.setBarSchnorr(0);
    }

    //----------------------------------
    // ECDSAStorage

    function testFuzz_liftECDSA(uint bloom) public {
        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct list of validators' addresses.
        address[] memory addrs = new address[](validators.length);
        for (uint i; i < addrs.length; i++) {
            addrs[i] = validators[i].toAddress();
        }

        // Expect an event for each validator being lifted.
        for (uint i; i < validators.length; i++) {
            vm.expectEmit();
            emit ValidatorLiftedECDSA(address(this), validators[i].toAddress());
        }

        // Lift validators.
        uscribe.liftECDSA(addrs);

        // Lifting is idempotent.
        uscribe.liftECDSA(addrs);

        // Verify exactly expected validators got lifted.
        assertEq(uscribe.validatorsECDSA().length, validators.length);
        for (uint i; i < validators.length; i++) {
            assertTrue(uscribe.validatorsECDSA(validators[i].toAddress()));
        }
    }

    function testFuzz_liftECDSA_FailsIf_ValidatorIsZeroAddress(
        uint bloom,
        uint indexSeed
    ) public {
        vm.assume(bloom != 0);

        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Select random index.
        uint index = _bound(indexSeed, 0, validators.length - 1);

        // Construct list of validators' addresses.
        address[] memory addrs = new address[](validators.length);
        for (uint i; i < addrs.length; i++) {
            addrs[i] = validators[i].toAddress();
        }

        // Substitute public key at index by zero point.
        addrs[index] = address(0);

        // Expect lift to fail.
        vm.expectRevert();
        uscribe.liftECDSA(addrs);
    }

    function test_liftECDSA_FailsIf_IdAlreadyLifted() public {
        // Create two validators with same id.
        Validator memory v1 = LibValidator.newValidator(22171);
        Validator memory v2 = LibValidator.newValidator(38091);
        assert(v1.toId() == v2.toId());

        address[] memory addrs = new address[](1);

        addrs[0] = v1.toAddress();
        uscribe.liftECDSA(addrs);

        addrs[0] = v2.toAddress();
        vm.expectRevert();
        uscribe.liftECDSA(addrs);
    }

    function testFuzz_dropECDSA(uint bloom) public {
        // Lift all 256 validators.
        Validator[] memory allValidators =
            LibValidator.newValidatorsFromBloom(type(uint).max);
        address[] memory allAddrs = new address[](allValidators.length);
        for (uint i; i < allAddrs.length; i++) {
            allAddrs[i] = allValidators[i].toAddress();
        }
        uscribe.liftECDSA(allAddrs);

        // Get random set of validators from bloom.
        Validator[] memory validators =
            LibValidator.newValidatorsFromBloom(bloom);

        // Construct list of validators' ids.
        uint8[] memory ids = new uint8[](validators.length);
        for (uint i; i < ids.length; i++) {
            ids[i] = validators[i].toId();
        }

        // Expect an event for each validator being dropped.
        for (uint i; i < ids.length; i++) {
            vm.expectEmit();
            emit ValidatorDroppedECDSA(address(this), validators[i].toAddress());
        }

        // Drop validators.
        uscribe.dropECDSA(ids);

        // Verify exactly expected validators got dropped.
        assertEq(uscribe.validatorsECDSA().length, 256 - validators.length);
        for (uint i; i < 256; i++) {
            (bool lifted,) = uscribe.validatorsECDSA(uint8(i));
            assertEq(lifted, bloom & (1 << i) == 0);
        }
    }

    function testFuzz_setBarECDSA(uint8 bar) public {
        vm.assume(bar != 0);

        // Only expect event if bar actually updated.
        if (uscribe.barECDSA() != bar) {
            vm.expectEmit();
            emit BarUpdatedECDSA(address(this), uscribe.barECDSA(), bar);
        }

        // Update bar.
        uscribe.setBarECDSA(bar);

        // Verify bar updated.
        assertEq(uscribe.barECDSA(), bar);
    }

    function test_setBarECDSA_FailsIf_BarIsZero() public {
        vm.expectRevert();
        uscribe.setBarECDSA(0);
    }
}
