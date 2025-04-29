// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Auth} from "chronicle-std/auth/Auth.sol";

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
    address private __uscribe;

    constructor(address initialAuthed) Auth(initialAuthed) {}

    /// @inheritdoc IUScribeRouter
    function setUScribe(address uscribe_, bytes32 wat) external auth {
        require(IUScribe(uscribe_).wat() == wat);

        if (__uscribe != uscribe_) {
            emit UScribeUpdated(msg.sender, __uscribe, uscribe_);
            __uscribe = uscribe_;
        }
    }

    /// @inheritdoc IUScribeRouter
    function uscribe() public view returns (address) {
        return __uscribe;
    }
}
