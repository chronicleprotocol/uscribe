// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {UPokeData, SchnorrData, ECDSAData} from "./Types.sol";
import {LibSecp256k1} from "./libs/LibSecp256k1.sol";

interface IUScribe {
    //--------------------------------------------------------------------------
    // Errors

    /// @notice Thrown if poke verification failed.
    /// @param err The verification error.
    error PokeError_VerificationFailed(bytes4 err);

    /// @notice Thrown if poke rejected by consumer.
    /// @param err The consumer error.
    error PokeError_ConsumerRejectedPayload(bytes4 err);

    //----------------------------------
    // Verification Errors

    /// @notice Verification error thrown via `PokeError_VerificationFailed` if
    ///         poke did not reach bar threshold.
    error VerificationError_BarNotReached();

    /// @notice Verification error thrown via `PokeError_VerificationFailed` if
    ///         poke attempted double signing.
    error VerificationError_DoubleSigningAttempted();

    /// @notice Verification error thrown via `PokeError_VerificationFailed` if
    ///         poke included invalid validator.
    error VerificationError_ValidatorInvalid();

    /// @notice Verification error thrown via `PokeError_VerificationFailed` if
    ///         poke included invalid signature.
    error VerificationError_SignatureInvalid();

    //--------------------------------------------------------------------------
    // Events

    /// @notice Emitted when oracle was successfully poked.
    /// @param caller The caller's address.
    /// @param proofURI Optional URI to validity proof.
    event UPoked(address indexed caller, string proofURI);

    /// @notice Emitted when new validator lifted for Schnorr verification.
    /// @param caller The caller's address.
    /// @param validator The validator address lifted.
    event ValidatorLiftedSchnorr(
        address indexed caller, address indexed validator
    );

    /// @notice Emitted when validator dropped from Schnorr verification.
    /// @param caller The caller's address.
    /// @param validator The validator address dropped.
    event ValidatorDroppedSchnorr(
        address indexed caller, address indexed validator
    );

    /// @notice Emitted when bar for Schnorr verification updated.
    /// @param caller The caller's address.
    /// @param oldBar The old bar's value.
    /// @param newBar The new bar's value.
    event BarUpdatedSchnorr(address indexed caller, uint8 oldBar, uint8 newBar);

    /// @notice Emitted when new validator lifted for ECDSA verification.
    /// @param caller The caller's address.
    /// @param validator The validator address lifted.
    event ValidatorLiftedECDSA(
        address indexed caller, address indexed validator
    );

    /// @notice Emitted when validator dropped from ECDSA verification.
    /// @param caller The caller's address.
    /// @param validator The validator address dropped.
    event ValidatorDroppedECDSA(
        address indexed caller, address indexed validator
    );

    /// @notice Emitted when bar for ECDSA verification updated.
    /// @param caller The caller's address.
    /// @param oldBar The old bar's value.
    /// @param newBar The new bar's value.
    event BarUpdatedECDSA(address indexed caller, uint8 oldBar, uint8 newBar);

    //--------------------------------------------------------------------------
    // Poke Functionality

    /// @notice Pokes the oracle using Schnorr verification.
    /// @param uPokeData The UPokeData being poked.
    /// @param schnorrData The SchnorrData proving the `uPokeData`'s integrity.
    function poke(
        UPokeData calldata uPokeData,
        SchnorrData calldata schnorrData
    ) external;

    /// @notice Pokes the oracle using ECDSA verification.
    /// @param uPokeData The UPokeData being poked.
    /// @param ecdsaDatas The list of ECDSAData proving the `uPokeData`'s
    ///                   integrity.
    function poke(UPokeData calldata uPokeData, ECDSAData[] calldata ecdsaDatas)
        external;

    /// @notice Construct a Chronicle Signed Message.
    /// @param scheme The scheme to construct the message for.
    /// @param uPokeData The UPokeData to inlcude in the message.
    function constructChronicleSignedMessage(
        bytes32 scheme,
        UPokeData calldata uPokeData
    ) external view returns (bytes32);

    //--------------------------------------------------------------------------
    // Auth'ed Functionality

    /// @notice Lifts list of public keys `pubKeys` for Schnorr verification.
    /// @dev Only callable by auth'ed address.
    /// @param pubKeys The list of public keys to lift.
    function liftSchnorr(LibSecp256k1.Point[] calldata pubKeys) external;

    /// @notice Drops list of validator ids `ids` from Schnorr verification.
    /// @dev Only callable by auth'ed address.
    /// @param ids The list of validator ids to drop.
    function dropSchnorr(uint8[] calldata ids) external;

    /// @notice Updates the bar security parameter for Schnorr verification.
    /// @dev Only callable by auth'ed address.
    /// @param bar The value to update bar to.
    function setBarSchnorr(uint8 bar) external;

    /// @notice Lifts list of addresses `validators` for ECDSA verification.
    /// @dev Only callable by auth'ed address.
    /// @param validators The list of addresses to lift.
    function liftECDSA(address[] calldata validators) external;

    /// @notice Drops list of validator ids `ids` from ECDSA verification.
    /// @dev Only callable by auth'ed address.
    /// @param ids The list of validator ids to drop.
    function dropECDSA(uint8[] calldata ids) external;

    /// @notice Updates the bar security parameter for ECDSA verification.
    /// @dev Only callable by auth'ed address.
    /// @param bar The value to update bar to.
    function setBarECDSA(uint8 bar) external;

    //--------------------------------------------------------------------------
    // Public View Functions

    /// @notice Returns the oracle's identifier.
    /// @dev The wat is derived from `name()`:
    ///
    ///      ```solidity
    ///      assert(wat() = keccak256(bytes(name())));
    ///      ```
    /// @return bytes32 The oracle's identifier.
    function wat() external view returns (bytes32);

    /// @notice Returns the oracle's name.
    /// @return string The oracle's name.
    function name() external view returns (string memory);

    /// @notice Returns the timestamp of the latest poke.
    /// @dev This timestamp is updated on every poke and allows uniform
    ///      staleness monitoring accross uscribe instances.
    /// @return uint The timestamp of the latest poke.
    function latestPoke() external view returns (uint);

    /// @notice Returns whether address `who` is a validator for Schnorr
    ///         verification.
    /// @param who The address to check.
    /// @return bool True if `who` is a validator for Schnorr verification,
    ///              false otherwise.
    function validatorsSchnorr(address who) external view returns (bool);

    /// @notice Returns whether validator id `id` is a validator for Schnorr
    ///         verification and, if so, the validator's address.
    /// @param id The validator id to check.
    /// @return bool True if `who` is a validator for Schnorr verification,
    ///              false otherwise.
    /// @return address Address of the validator if `id` is a validator for
    ///                 Schnorr verification, zero address otherwise.
    function validatorsSchnorr(uint8 id)
        external
        view
        returns (bool, address);

    /// @notice Returns the lift of validator addresses for Schnorr
    ///         verification.
    /// @return address[] The lift of validator addresses for Schnorr
    ///                   verification.
    function validatorsSchnorr() external view returns (address[] memory);

    /// @notice Returns the bar security parameter for Schnorr verification.
    /// @return uint8 The bar security parameter for Schnorr verification.
    function barSchnorr() external view returns (uint8);

    /// @notice Returns whether address `who` is a validator for ECDSA
    ///         verification.
    /// @param who The address to check.
    /// @return bool True if `who` is a validator for ECDSA verification, false
    ///              otherwise.
    function validatorsECDSA(address who) external view returns (bool);

    /// @notice Returns whether validator id `id` is a validator for ECDSA
    ///         verification and, if so, the validator's address.
    /// @param id The validator id to check.
    /// @return bool True if `who` is a validator for ECDSA verification,
    ///              false otherwise.
    /// @return address Address of the validator if `id` is a validator for
    ///                 ECDSA verification, zero address otherwise.
    function validatorsECDSA(uint id) external view returns (bool, address);

    /// @notice Returns the lift of validator addresses for ECDSA verification.
    /// @return address[] The lift of validator addresses for ECDSA
    ///                   verification.
    function validatorsECDSA() external view returns (address[] memory);

    /// @notice Returns the bar security parameter for ECDSA verification.
    /// @return uint8 The bar security parameter for ECDSA verification.
    function barECDSA() external view returns (uint8);
}
