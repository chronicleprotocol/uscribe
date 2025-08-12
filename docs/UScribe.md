# uScribe

This document provides technical documentation for _Chronicle Protocol_'s uScribe oracle system.

## Table of Contents

- [uScribe](#uscribe)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Consumers](#consumers)
  - [Security](#security)

## Overview

uScribe is a universal oracle able to serve arbitrary data based on the battle-tested and highly secure [Scribe]() oracle system.

The uScribe oracle allows for unique customization via its [consumer](#consumers) architecture, giving data providers a chance to define onchain enforced rules over their data - all while enjoying the high security of the underlying _Chronicle Protocol_.

This is achieved via separating the data integrity verification from the data update and access logic, giving data providers the ability to enforce unique rulesets about their data directly onchain.

## Consumers

Consumers are the downstream contract implementations that implement application specific logic. By inherting from the `UScribe.sol` base contract a consumer automatically implements the highly complex data security verfication and enables a data provider to use the [highest quality validator set](https://chroniclelabs.org/validators) to secure their data.

The internal [`_poke(bytes calldata payload)`](https://github.com/chronicleprotocol/uscribe/blob/main/src/UScribe.sol#L81-L116) must be overwritten to define the state update executed when new data is being published. Because the integrity of the data is already verified by the _Chronicle Protocol_ the implement must only concern itself with the actual application logic.

Via the consumers pattern the uScribe oracle gives data providers the highest flexibility to control who and under which conditions is allowed to access their data. Consumers can implement arbitrary read functions to eg provide access to historical data, grant access based on specific conditions an address must fulfill, or even restrict access during times of uncertainty.

By separating the highly complex cryptographic verification from the application logic, uScribe enables everyone to build oracles under their own terms.

## Security

The data integrity verification is based on the battle-tested [Scribe](https://github.com/chronicleprotocol/scribe/) codebase which runs in production since 2023 without security issues and uses the most efficient [multi signature verification](https://github.com/chronicleprotocol/scribe/blob/main/docs/Schnorr.md) live on Ethereum up to this date.
