// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IUScribeRouter {
    /// @notice Emitted when the UScribe address is updated.
    /// @param caller The caller's address.
    /// @param oldUScribe The old UScribe address.
    /// @param newUScribe The new UScribe address.
    event UScribeUpdated(
        address indexed caller, address oldUScribe, address newUScribe
    );

    /// @notice Sets the UScribe address.
    /// @param uscribe The address of the UScribe contract.
    /// @param wat The wat of the UScribe contract.
    /// @dev Reverts if the UScribe contract does not have the expected wat.
    function setUScribe(address uscribe, bytes32 wat) external;

    /// @notice Returns the UScribe address.
    /// @return address The UScribe address.
    function uscribe() external view returns (address);
}
