# Management

This document describes how to manage deployed `uScribe` instances.

## Table of Contents

- [Management](#management)
  - [Table of Contents](#table-of-contents)
  - [Environment Variables](#environment-variables)
  - [Functions](#functions)
    - [`IUScribe::setBarSchnorr`](#iscribesetbar)
    - [`IUScribe::liftSchnorr`](#iscribelift)
    - [`IUScribe::dropSchnorr`](#iscribedrop)
    - [`IUScribe::setBarECDSA`](#iscribesetbar)
    - [`IUScribe::liftECDSA`](#iscribelift)
    - [`IUScribe::dropECDSA`](#iscribedrop)
    - [`IAuth::rely`](#iauthrely)
    - [`IAuth::deny`](#iauthdeny)

## Environment Variables

The following environment variables must be set for all commands:

- `RPC_URL`: The RPC URL of an EVM node
- `KEYSTORE`: The path to the keystore file containing the encrypted private key
- `KEYSTORE_PASSWORD`: The password of the keystore file
- `USCRIBE`: The `uScribe` instance to manage

Note that an `.env.example` file is provided in the project root. To set all environment variables at once, create a copy of the file and rename the copy to `.env`, adjust the variable's values', and run `source .env`.

To easily check the environment variables, run:

```bash
$ env | grep -e "RPC_URL" -e "KEYSTORE" -e "KEYSTORE_PASSWORD" -e "USCRIBE"
```

## Functions

### `IUScribe::setBarSchnorr`

Set the following environment variables:

- `SCHNORR_BAR`: The bar to set

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "setBarSchnorr(address,uint8)" "$USCRIBE" "$SCHNORR_BAR") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IUScribe::liftSchnorr`

Set the following environment variables:

- `SCHNORR_VALIDATOR_PUBLIC_KEY_X_COORDINATES`: The validator' public keys' `x` coordinates
- `SCHNORR_VALIDATOR_PUBLIC_KEY_Y_COORDINATES`: The validator' public keys' `y` coordinates

Note to use the following format for lists: `"[<elem>,<elem>]"`

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "liftSchnorr(address,uint[],uint[])" "$USCRIBE" "$SCHNORR_VALIDATOR_PUBLIC_KEY_X_COORDINATES" "$SCHNORR_VALIDATOR_PUBLIC_KEY_Y_COORDINATES") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IUScribe::dropSchnorr`

Set the following environment variables:

- `SCHNORR_VALIDATOR_IDS`: The validators' ids

Note to use the following format for lists: `"[<elem>,<elem>]"`

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "dropSchnorr(address,uint8[])" "$USCRIBE" "$SCHNORR_VALIDATOR_IDS") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IUScribe::setBarECDSA`

Set the following environment variables:

- `ECDSA_BAR`: The bar to set

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "setBarECDSA(address,uint8)" "$USCRIBE" "$ECDSA_BAR") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IUScribe::liftECDSA`

Set the following environment variables:

- `ECDSA_VALIDATOR_ADDRESSES`: The validators' addresses

Note to use the following format for lists: `"[<elem>,<elem>]"`

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "liftECDSA(address,address[])" "$USCRIBE" "$ECDSA_VALIDATOR_ADDRESSES") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IUScribe::dropECDSA`

Set the following environment variables:

- `ECDSA_VALIDATOR_IDS`: The validators' ids

Note to use the following format for lists: `"[<elem>,<elem>]"`

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "dropECDSA(address,uint8[])" "$USCRIBE" "$ECDSA_VALIDATOR_IDS") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IAuth::rely`

Set the following environment variables:

- `WHO`: The address to grant auth to

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "rely(address,address)" "$USCRIBE" "$WHO") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```

### `IAuth::deny`

Set the following environment variables:

- `WHO`: The address to renounce auth from

Run:

```bash
$ forge script \
    --keystore "$KEYSTORE" \
    --password "$KEYSTORE_PASSWORD" \
    --broadcast \
    --rpc-url "$RPC_URL" \
    --sig $(cast calldata "deny(address,address)" "$USCRIBE" "$WHO") \
    -vvv \
    script/UScribe.s.sol:UScribeScript
```
