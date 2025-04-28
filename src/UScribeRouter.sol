// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Auth} from "chronicle-std/auth/Auth.sol";
import {Toll} from "chronicle-std/toll/Toll.sol";

import {IUScribe} from "./IUScribe.sol";
import {IUScribeRouter} from "./IUScribeRouter.sol";

/**
 * @title UScribeRouter
 * @custom:version 1.0.0
 *
 * @notice A base router contract for UScribe.
 *
 * @author Chronicle Labs, Inc
 * @custom:security-contact security@chroniclelabs.org
 */
abstract contract UScribeRouter is IUScribeRouter, Auth {
    address private _uscribe;

    constructor(address initialAuthed) Auth(initialAuthed) {}

    /// @inheritdoc IUScribeRouter
    function setUScribe(address uscribe, bytes32 wat) external auth {
        require(IUScribe(uscribe).wat() == wat);

        if (_uscribe != uscribe) {
            emit UScribeUpdated(msg.sender, _uscribe, uscribe);
            _uscribe = uscribe;
        }
    }

    /// @inheritdoc IUScribeRouter
    function uscribe() public view returns (address) {
        return _uscribe;
    }
}