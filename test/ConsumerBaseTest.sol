// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {IUScribe} from "../src/IUScribe.sol";
import {UPokeData, SchnorrData, ECDSAData} from "../src/Types.sol";

import {LibValidator, Validator} from "../script/libs/LibValidator.sol";

/**
 * @title ConsumerBaseTest
 *
 * @notice Helper contract to test consumer implementations
 *
 * @dev This contract can be inherited from in a consumer implementation test.
 *      It removes the need to handle validators, signature generation and other
 *      poke internals.
 */
abstract contract ConsumerBaseTest is Test {
    using LibValidator for Validator;

    IUScribe private __uscribe;
    bytes32 private __wat;

    Validator private __validator;

    function _setUp(address uscribe) internal {
        require(
            uscribe != address(0),
            "ConsumerBaseTest::_setUp: uscribe is zero address"
        );
        __uscribe = IUScribe(uscribe);
        __wat = __uscribe.wat();

        __validator = LibValidator.newValidator({privKey: 2});

        // Lift single ECDSA validator.
        address[] memory validators = new address[](1);
        validators[0] = __validator.toAddress();
        __uscribe.liftECDSA(validators);

        // Set barECDSA to 1.
        __uscribe.setBarECDSA(1);
    }

    function _poke(bytes memory payload) internal {
        // Construct uPokeData encapsulating payload.
        UPokeData memory uPokeData = UPokeData({
            payload: payload,
            proofURI: "ipfs://consumer-base-test-proof-uri"
        });

        // Construct Chronicle Signed Message for ECDSA poke with uPokeData.
        //
        // Note to not use __uscribe's constructChronicleSignedMessage function
        // to prevent external call prior to __uscribe.poke().
        // This allows callers to vm.expectRevert() the __uscribe.poke() call.
        bytes32 message = __constructChronicleSignedMessage({
            scheme: bytes32("ECDSA"),
            uPokeData: uPokeData
        });

        // Let validator sign message.
        ECDSAData memory ecdsa = __validator.signECDSA(message);

        // Construct list of ECDSA signatures.
        ECDSAData[] memory ecdsas = new ECDSAData[](1);
        ecdsas[0] = ecdsa;

        // Execute poke.
        __uscribe.poke(uPokeData, ecdsas);
    }

    //--------------------------------------------------------------------------
    // Private Helpers

    function __constructChronicleSignedMessage(
        bytes32 scheme,
        UPokeData memory uPokeData
    ) private view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19Chronicle Signed Message:\n32",
                keccak256(
                    abi.encodePacked(
                        scheme,
                        __wat,
                        keccak256(abi.encodePacked(uPokeData.payload)),
                        keccak256(abi.encodePacked(uPokeData.proofURI))
                    )
                )
            )
        );
    }
}
