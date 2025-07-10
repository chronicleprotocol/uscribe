// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Auth} from "chronicle-std@v2/auth/Auth.sol";

import {IUScribe} from "./IUScribe.sol";
import {UPokeData, SchnorrData, ECDSAData} from "./Types.sol";

import {LibSchnorr} from "./libs/LibSchnorr.sol";
import {LibSecp256k1} from "./libs/LibSecp256k1.sol";

/**
 * @title UScribe
 * @custom:version 1.2.0
 *
 * @notice A universal Oracle
 *
 * @author Chronicle Labs, Inc
 * @custom:security-contact security@chroniclelabs.org
 */
abstract contract UScribe is IUScribe, Auth {
    using LibSchnorr for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.Point;
    using LibSecp256k1 for LibSecp256k1.JacobianPoint;

    //--------------------------------------------------------------------------
    // Constants and Immutables

    bytes4 internal constant _NO_ERR = bytes4(0);

    /// @inheritdoc IUScribe
    bytes32 public immutable wat;

    // Note that strings cannot be marked as immutable.
    // @custom:invariant Is immutable.
    string private _name;

    //--------------------------------------------------------------------------
    // Storage

    uint48 private _latestPoke;

    struct SchnorrStorage {
        LibSecp256k1.Point[256] pubKeys;
        uint8 bar;
    }

    SchnorrStorage private __schnorrStorage;

    struct ECDSAStorage {
        address[256] validators;
        uint8 bar;
    }

    ECDSAStorage private __ecdsaStorage;

    //--------------------------------------------------------------------------
    // Constructor

    constructor(address initialAuthed, string memory name_)
        Auth(initialAuthed)
    {
        require(bytes(name_).length != 0);

        _name = name_;
        wat = keccak256(bytes(name_));

        // Note to not have bars of zero.
        __schnorrStorage.bar = type(uint8).max;
        __ecdsaStorage.bar = type(uint8).max;
    }

    /// @inheritdoc IUScribe
    function name() external view returns (string memory) {
        return _name;
    }

    //--------------------------------------------------------------------------
    // Consumer Implemented Functionality

    /// @dev Function implemented in downstream consumer contract to handle
    ///      application specific state update.
    ///
    /// @dev The implementation MUST deserialize the payload and perform
    ///      necessary sanity checks.
    ///
    ///      It SHOULD NOT revert but instead return the error types' selector
    ///      whenever possible. This allows uScribe to wrap the application
    ///      specific error into a `PokeError_ConsumerRejectedPayload()` error.
    ///
    ///      To indicate a successful poke, the function MUST return the
    ///      `_NO_ERR = bytes4(0)` constant.
    ///
    /// @dev Note that this function is vulnerable to replay attacks.
    ///
    ///      Consumers MUST implement application specific logic to prevent
    ///      replayability issues. uScribe only verifies that the respective
    ///      validators attested to the payload at some point in time, ie
    ///      uScribe performs a stateless signature verification.
    ///
    ///      Note that this requires the payload to contain sufficient data for
    ///      the consumer logic to protect against replayability issues.
    ///
    ///      Protections against replayability issues MAY be including a nonce
    ///      in the payload or only accepting payloads with strictly
    ///      monotonically increasing timestamps. The `latestPoke()(uint)`
    ///      function can be used by consumers to access the timestamp of the
    ///      last poke.
    ///
    ///      To protect against cross-chain replayability issues the payload
    ///      MAY be expected to include the chain's id.
    ///
    /// @param payload The verified payload blob.
    /// @return bytes4 `_NO_ERR` if poke successful, application's error type
    ///                selector otherwise.
    function _poke(bytes calldata payload) internal virtual returns (bytes4);

    //--------------------------------------------------------------------------
    // Poke Functionality

    /// @inheritdoc IUScribe
    function poke(UPokeData calldata uPokeData, SchnorrData calldata schnorr)
        external
    {
        bytes4 err;
        bytes32 message;

        // Construct Schnorr Chronicle Signed Message of uPokeData.
        message = constructChronicleSignedMessage({
            scheme: bytes32("SCHNORR"),
            uPokeData: uPokeData
        });

        // Verify Schnorr signature.
        err = __verifySchnorrSignature(message, schnorr);
        if (err != _NO_ERR) {
            revert PokeError_VerificationFailed(err);
        }

        // Poke's security verified.
        emit UPoked(msg.sender, uPokeData.proofURI);

        // Forward payload to consumer.
        err = _poke(uPokeData.payload);
        if (err != _NO_ERR) {
            revert PokeError_ConsumerRejectedPayload(err);
        }

        // Update latest poke timestamp once poke accepted by consumer.
        _latestPoke = uint48(block.timestamp);
    }

    /// @inheritdoc IUScribe
    function poke(UPokeData calldata uPokeData, ECDSAData[] calldata ecdsas)
        external
    {
        bytes4 err;
        bytes32 message;

        // Construct ECDSA Chronicle Signed Message of uPokeData.
        message = constructChronicleSignedMessage({
            scheme: bytes32("ECDSA"),
            uPokeData: uPokeData
        });

        // Verify ECDSA signatures.
        err = __verifyECDSASignatures(message, ecdsas);
        if (err != _NO_ERR) {
            revert PokeError_VerificationFailed(err);
        }

        // Poke's security verified.
        emit UPoked(msg.sender, uPokeData.proofURI);

        // Forward payload to consumer.
        err = _poke(uPokeData.payload);
        if (err != _NO_ERR) {
            revert PokeError_ConsumerRejectedPayload(err);
        }

        // Update latest poke timestamp once poke accepted by consumer.
        _latestPoke = uint48(block.timestamp);
    }

    //--------------------------------------------------------------------------
    // Chronicle Signed Message Functionality

    /// @inheritdoc IUScribe
    function constructChronicleSignedMessage(
        bytes32 scheme,
        UPokeData calldata uPokeData
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Chronicle Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        scheme,
                        wat,
                        keccak256(abi.encodePacked(uPokeData.payload)),
                        keccak256(abi.encodePacked(uPokeData.proofURI))
                    )
                )
            )
        );
    }

    //--------------------------------------------------------------------------
    // Signature Verification Functionality

    /// @custom:invariant Reverts iff out of gas.
    /// @custom:invariant Runtime is O(__schnorrStorage.bar).
    function __verifySchnorrSignature(
        bytes32 message,
        SchnorrData calldata schnorr
    ) private view returns (bytes4) {
        // Let pubKey be the currently processed validator's public key.
        LibSecp256k1.Point memory pubKey;
        // Let id be the currently processed validator's id.
        uint8 id;
        // Let aggPubKey be the sum of processed validator public keys.
        // Note that Jacobian coordinates are used.
        LibSecp256k1.JacobianPoint memory aggPubKey;
        // Let bloom be a bloom filter to guarantee signer uniqueness.
        uint bloom;

        // Fail if number of validators unequal to bar.
        //
        // Note that requiring equality constrains the verification's runtime
        // from Ω(bar) to Θ(bar).
        uint bar = __schnorrStorage.bar;
        if (schnorr.validatorIds.length != bar) {
            return VerificationError_BarNotReached.selector;
        }

        // Initiate validator variables.
        id = uint8(schnorr.validatorIds[0]);
        pubKey = __schnorrStorage.pubKeys[id];
        if (pubKey.isZeroPoint()) {
            return VerificationError_ValidatorInvalid.selector;
        }

        // Initiate bloom filter and aggPubKey.
        bloom = 1 << id;
        aggPubKey = pubKey.toJacobian();

        // Aggregation loop.
        for (uint i = 1; i < bar; i++) {
            // Update validator variables.
            id = uint8(schnorr.validatorIds[i]);
            pubKey = __schnorrStorage.pubKeys[id];
            if (pubKey.isZeroPoint()) {
                return VerificationError_ValidatorInvalid.selector;
            }

            // Fail if double signing attempted.
            if (bloom & (1 << id) != 0) {
                return VerificationError_DoubleSigningAttempted.selector;
            }

            // Update bloom filter.
            bloom |= 1 << id;

            // Add pubKey to aggPubKey.
            aggPubKey.addAffinePoint(pubKey);
        }

        // Perform signature verification.
        bool ok = aggPubKey.toAffine().verifySignature(
            message, schnorr.signature, schnorr.commitment
        );
        if (!ok) {
            return VerificationError_SignatureInvalid.selector;
        }

        return _NO_ERR;
    }

    /// @custom:invariant Reverts iff out of gas.
    /// @custom:invariant Runtime is O(__ecdsaStorage.bar).
    function __verifyECDSASignatures(
        bytes32 message,
        ECDSAData[] calldata ecdsas
    ) private view returns (bytes4) {
        // Let ecdsa be the currently processed ECDSA signature.
        ECDSAData memory ecdsa;
        // Let signer be the currently processed ECDSA signature's signer.
        address signer;
        // Let id the the currently processed ECDSA signature's signer id.
        uint id;
        // Let bloom be a bloom filter to guarantee signer uniqueness.
        uint bloom;

        // Fail if number of validators unequal to bar.
        //
        // Note that requiring equality constrains the verification's runtime
        // from Ω(bar) to Θ(bar).
        uint bar = __ecdsaStorage.bar;
        if (ecdsas.length != bar) {
            return VerificationError_BarNotReached.selector;
        }

        for (uint i; i < bar; i++) {
            // Update ECDSA variables.
            ecdsa = ecdsas[i];
            signer = ecrecover(message, ecdsa.v, ecdsa.r, ecdsa.s);
            id = uint160(signer) >> 152;

            // Fail if signature invalid or signer not a validator.
            // forgefmt: disable-next-item
            if (signer == address(0) || __ecdsaStorage.validators[id] != signer) {
                return VerificationError_SignatureInvalid.selector;
            }

            // Fail if double signing attempted.
            if (bloom & (1 << id) != 0) {
                return VerificationError_DoubleSigningAttempted.selector;
            }

            // Update bloom filter.
            bloom |= 1 << id;
        }

        return _NO_ERR;
    }

    //--------------------------------------------------------------------------
    // Auth'ed Functionality

    //----------------------------------
    // SchnorrStorage

    /// @inheritdoc IUScribe
    function liftSchnorr(LibSecp256k1.Point[] calldata pubKeys) external auth {
        for (uint i; i < pubKeys.length; i++) {
            LibSecp256k1.Point memory pubKey = pubKeys[i];
            require(!pubKey.isZeroPoint());
            // assert(pubKey.toAddress() != address(0));

            address validator = pubKey.toAddress();
            uint id = uint160(validator) >> 152;

            LibSecp256k1.Point memory sPubKey = __schnorrStorage.pubKeys[id];
            if (sPubKey.isZeroPoint()) {
                __schnorrStorage.pubKeys[id] = pubKey;
                emit ValidatorLiftedSchnorr(msg.sender, validator);
            } else {
                require(validator == sPubKey.toAddress());
            }
        }
    }

    /// @inheritdoc IUScribe
    function dropSchnorr(uint8[] calldata ids) external auth {
        for (uint i; i < ids.length; i++) {
            uint8 id = ids[i];

            LibSecp256k1.Point memory pubKey = __schnorrStorage.pubKeys[id];
            if (!pubKey.isZeroPoint()) {
                delete __schnorrStorage.pubKeys[id];
                emit ValidatorDroppedSchnorr(msg.sender, pubKey.toAddress());
            }
        }
    }

    /// @inheritdoc IUScribe
    function setBarSchnorr(uint8 bar) external auth {
        require(bar != 0);

        if (__schnorrStorage.bar != bar) {
            emit BarUpdatedSchnorr(msg.sender, __schnorrStorage.bar, bar);
            __schnorrStorage.bar = bar;
        }
    }

    //----------------------------------
    // ECDSAStorage

    /// @inheritdoc IUScribe
    function liftECDSA(address[] calldata validators) external auth {
        for (uint i; i < validators.length; i++) {
            address validator = validators[i];
            require(validator != address(0));

            uint id = uint160(validator) >> 152;

            if (__ecdsaStorage.validators[id] == address(0)) {
                __ecdsaStorage.validators[id] = validator;
                emit ValidatorLiftedECDSA(msg.sender, validator);
            } else {
                require(__ecdsaStorage.validators[id] == validator);
            }
        }
    }

    /// @inheritdoc IUScribe
    function dropECDSA(uint8[] calldata ids) external auth {
        for (uint i; i < ids.length; i++) {
            uint8 id = ids[i];
            address validator = __ecdsaStorage.validators[id];

            if (validator != address(0)) {
                // assert(uint160(validator) >> 152 == id);
                delete __ecdsaStorage.validators[id];
                emit ValidatorDroppedECDSA(msg.sender, validator);
            }
        }
    }

    /// @inheritdoc IUScribe
    function setBarECDSA(uint8 bar) external auth {
        require(bar != 0);

        if (__ecdsaStorage.bar != bar) {
            emit BarUpdatedECDSA(msg.sender, __ecdsaStorage.bar, bar);
            __ecdsaStorage.bar = bar;
        }
    }

    //--------------------------------------------------------------------------
    // Public View Functions

    /// @inheritdoc IUScribe
    ///
    /// @dev Note that function is public to grant read-only access to
    ///      downstream consumer.
    function latestPoke() public view returns (uint) {
        return _latestPoke;
    }

    //----------------------------------
    // SchnorrStorage

    /// @inheritdoc IUScribe
    function validatorsSchnorr(address who) external view returns (bool) {
        uint id = uint160(who) >> 152;
        LibSecp256k1.Point memory pubKey = __schnorrStorage.pubKeys[id];

        return !pubKey.isZeroPoint() && pubKey.toAddress() == who;
    }

    /// @inheritdoc IUScribe
    function validatorsSchnorr(uint8 id)
        external
        view
        returns (bool, address)
    {
        LibSecp256k1.Point memory pubKey = __schnorrStorage.pubKeys[id];

        return !pubKey.isZeroPoint()
            ? (true, pubKey.toAddress())
            : (false, address(0));
    }

    /// @inheritdoc IUScribe
    function validatorsSchnorr() external view returns (address[] memory) {
        address[] memory validators = new address[](256);

        LibSecp256k1.Point memory pubKey;
        uint ctr;
        for (uint i; i < 256; i++) {
            pubKey = __schnorrStorage.pubKeys[i];

            if (!pubKey.isZeroPoint()) {
                validators[ctr++] = pubKey.toAddress();
            }
        }

        assembly ("memory-safe") {
            mstore(validators, ctr)
        }

        return validators;
    }

    /// @inheritdoc IUScribe
    function barSchnorr() external view returns (uint8) {
        return __schnorrStorage.bar;
    }

    //----------------------------------
    // ECDSAStorage

    /// @inheritdoc IUScribe
    function validatorsECDSA(address who) external view returns (bool) {
        uint id = uint160(who) >> 152;

        return who != address(0) && __ecdsaStorage.validators[id] == who;
    }

    /// @inheritdoc IUScribe
    function validatorsECDSA(uint id) external view returns (bool, address) {
        address validator = __ecdsaStorage.validators[id];

        return validator != address(0) ? (true, validator) : (false, address(0));
    }

    /// @inheritdoc IUScribe
    function validatorsECDSA() external view returns (address[] memory) {
        address[] memory validators = new address[](256);

        address validator;
        uint ctr;
        for (uint i; i < 256; i++) {
            validator = __ecdsaStorage.validators[i];

            if (validator != address(0)) {
                validators[ctr++] = validator;
            }
        }

        assembly ("memory-safe") {
            mstore(validators, ctr)
        }

        return validators;
    }

    /// @inheritdoc IUScribe
    function barECDSA() external view returns (uint8) {
        return __ecdsaStorage.bar;
    }
}
