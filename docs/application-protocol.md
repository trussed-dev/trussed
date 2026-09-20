# Trussed Application Protocol

*Version 1.0*

This document describes a protocol for Trussed applications that provide custom commands.

## Application ID

Every application that implements this protocol is assigned a unique application ID.
The application ID is chosen from the range between 0x40 and 0x7F so that it is a valid [CTAPHID vendor command][ctaphid-vendor-command].
The following application IDs are currently assigned:

| ID   | Application |
| ---- | ----------- |
| 0x51 | *reserved (admin-app)* |
| 0x53 | *reserved (admin-app)* |
| 0x60 | *reserved (admin-app)* |
| 0x61 | *reserved (admin-app)* |
| 0x62 | *reserved (admin-app)* |
| 0x63 | *reserved (admin-app)* |
| 0x70 | *reserved (secrets-app)* |
| 0x71 | *reserved (provisioner-app)* |
| 0x72 | *reserved (admin-app)* |
| 0x73 | *reserved (storage-app)* |

[ctaphid-vendor-command]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#usb-vendor-specific-commands

## Commands

An application defines a set of commands.
A command consists of a command ID, optional request data and optional response data.
The command ID is an 8-bit unsigned integer and must be unique for the application.
The request and response data, if specified, are maps according to the [CBOR specification][cbor].

[cbor]: https://www.rfc-editor.org/rfc/rfc8949.html

## Error Codes

An application can define a set of custom error codes.
An error code is a non-zero 8-bit unsigned integer.

## Protocol

The client executes a command by sending the command ID and the optional CBOR-encoded request data.
The device responds with a status code (0 if successful or an error code otherwise) and the optional CBOR-encoded response data.

## Transports

An application can support one or more of the following transports.

### CCID

When using the CCID transport, the application first has to be selected with the AID *tbd*.
Commands are then encoded as APDUs using the following scheme:

| Field | Value |
| ----- | ----- |
| CLA | 0x00 |
| INS | Command ID |
| P1 | 0x00 |
| P2 | 0x00 |
| Data | CBOR-encoded request data |

If the command is not supported, the device returns 0x6D00 (Instruction not supported or invalid).
Otherwise, the device returns the following response:

| Field | Value |
| ----- | ----- |
| Data\[0\] | 0 if successful, error code otherwise |
| Data\[1..\] | CBOR-encoded response data |
| SW1 | 0x90 |
| SW2 | 0x00 |


### CTAPHID

When using the [CTAPHID](ctaphid) transport, commands are sent as vendor commands using the following scheme:

**Request**

| Field | Value |
| ----- | ----- |
| CMD | Application ID |
| BCNT | 1..(n+1) |
| DATA | Command ID |
| DATA + 1 | CBOR-encoded request data (n bytes) |

If the application or command is not supported, the device returns `CTAPHID_ERROR` with the error code `ERR_INVALID_CMD`.
If BCNT is zero, i. e. the command ID is missing, the device returns `CTAPHID_ERROR` with the error code `ERR_INVALID_LEN`.
Otherwise, it returns the following response:

**Response**

| Field | Value |
| ----- | ----- |
| CMD | Application ID |
| BCNT | 1..(n + 1) |
| DATA | 0 if successful, error code otherwise |
| DATA + 1 | CBOR-encoded response data (n bytes) |

For compatibility, an empty response (BCNT = 0) must be treated like a response with a single zero byte, i. e. a successful response without response data.

[ctaphid]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#usb
