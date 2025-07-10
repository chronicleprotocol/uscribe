// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm} from "forge-std@v1/Vm.sol";
import {Script} from "forge-std@v1/Script.sol";
import {console2 as console} from "forge-std@v1/console2.sol";

import {IAuth} from "chronicle-std@v2/auth/IAuth.sol";

import {IUScribe} from "../src/IUScribe.sol";
import {UPokeData, SchnorrData, ECDSAData} from "../src/Types.sol";
import {LibSecp256k1} from "../src/libs/LibSecp256k1.sol";

/**
 * @notice uScribe Management Script
 */
contract UScribeScript is Script {
    using LibSecp256k1 for LibSecp256k1.Point;

    //--------------------------------------------------------------------------
    // IUScribe Functions

    //----------------------------------
    // Schnorr

    /// @dev Sets bar for Schnorr of `self` to `bar`.
    function setBarSchnorr(address self, uint8 bar) public {
        require(bar != 0, "Bar cannot be zero");

        vm.startBroadcast();
        IUScribe(self).setBarSchnorr(bar);
        vm.stopBroadcast();

        console.log("Bar Schnorr set to", bar);
    }

    /// @dev Lifts validator public keys for Schnorr on `self`.
    function liftSchnorr(
        address self,
        uint[] memory pubKeyXCoordinates,
        uint[] memory pubKeyYCoordinates
    ) public {
        uint len = pubKeyXCoordinates.length;
        require(
            len == pubKeyYCoordinates.length,
            "pubKeyYCoordinates length mismatch"
        );

        LibSecp256k1.Point[] memory pubKeys = new LibSecp256k1.Point[](len);
        for (uint i; i < len; i++) {
            pubKeys[i].x = pubKeyXCoordinates[i];
            pubKeys[i].y = pubKeyYCoordinates[i];

            require(
                !pubKeys[i].isZeroPoint(), "Public key cannot be zero point"
            );
            require(
                pubKeys[i].isOnCurve(),
                "Public key must be valid secp256k1 point"
            );
            bool isLifted =
                IUScribe(self).validatorsSchnorr(pubKeys[i].toAddress());
            require(!isLifted, "Public key already lifted");
        }

        vm.startBroadcast();
        IUScribe(self).liftSchnorr(pubKeys);
        vm.stopBroadcast();

        console.log("Lifted Schnorr:");
        for (uint i; i < len; i++) {
            console.log("  ", pubKeys[i].toAddress());
        }
    }

    /// @dev Drops validators `validatorIds` for Schnorr on `self`.
    function dropSchnorr(address self, uint8[] memory validatorIds) public {
        vm.startBroadcast();
        IUScribe(self).dropSchnorr(validatorIds);
        vm.stopBroadcast();

        for (uint i; i < validatorIds.length; i++) {
            console.log("Dropped Schnorr", validatorIds[i]);
        }
    }

    //----------------------------------
    // ECDSA

    /// @dev Sets bar for ECDSA of `self` to `bar`.
    function setBarECDSA(address self, uint8 bar) public {
        require(bar != 0, "Bar cannot be zero");

        vm.startBroadcast();
        IUScribe(self).setBarECDSA(bar);
        vm.stopBroadcast();

        console.log("Bar ECDSA set to", bar);
    }

    /// @dev Lifts validators `validators` for ECDSA on `self`.
    function liftECDSA(address self, address[] memory validators) public {
        for (uint i; i < validators.length; i++) {
            require(
                validators[i] != address(0), "Validator cannot be zero address"
            );
            bool isLifted = IUScribe(self).validatorsECDSA(validators[i]);
            require(!isLifted, "Validator already lifted");
        }

        vm.startBroadcast();
        IUScribe(self).liftECDSA(validators);
        vm.stopBroadcast();

        console.log("Lifted ECDSA:");
        for (uint i; i < validators.length; i++) {
            console.log("  ", validators[i]);
        }
    }

    /// @dev Drops validators `validatorIds` for ECDSA on `self`.
    function dropECDSA(address self, uint8[] memory validatorIds) public {
        vm.startBroadcast();
        IUScribe(self).dropECDSA(validatorIds);
        vm.stopBroadcast();

        for (uint i; i < validatorIds.length; i++) {
            console.log("Dropped ECDSA", validatorIds[i]);
        }
    }

    //--------------------------------------------------------------------------
    // IAuth Functions

    /// @dev Grants auth to address `who`.
    function rely(address self, address who) public {
        vm.startBroadcast();
        IAuth(self).rely(who);
        vm.stopBroadcast();

        console.log("Relied", who);
    }

    /// @dev Renounces auth from address `who`.
    function deny(address self, address who) public {
        vm.startBroadcast();
        IAuth(self).deny(who);
        vm.stopBroadcast();

        console.log("Denied", who);
    }
}
