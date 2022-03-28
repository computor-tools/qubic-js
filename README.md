# qubic-js
Qubic client library.
This is work in progress.

## Installation
With `pnpm`:
```
pnpm add qubic-js
```
With `yarn`:
```
yarn add qubic-js
```
With `npm`:
```
npm i qubic-js
```

## Include in your project
```JS
import * as qubic from 'qubic-js';
```

---

<br><a name="module_qubic"></a>

## qubic

* [qubic](#module_qubic)
    * [.exports.crypto](#module_qubic.exports.crypto) : [<code>Promise.&lt;Crypto&gt;</code>](#Crypto)
    * [.client(options)](#module_qubic.client) ⇒ [<code>Client</code>](#Client)
    * [.connection(params)](#module_qubic.connection) ⇒ [<code>Connection</code>](#Connection)
    * [.privateKey(seed, index, K12)](#module_qubic.privateKey) ⇒ <code>Uint8Array</code>
    * [.identity(seed, index)](#module_qubic.identity) ⇒ <code>Promise.&lt;string&gt;</code>
    * [.verifyChecksum(identity)](#module_qubic.verifyChecksum) ⇒ <code>Promise.&lt;boolean&gt;</code>
    * [.seedChecksum(seed)](#module_qubic.seedChecksum) ⇒ <code>Promise.&lt;string&gt;</code>
    * [.transaction(params)](#module_qubic.transaction) ⇒ [<code>Promise.&lt;Transaction&gt;</code>](#Transaction)


<br><a name="module_qubic.exports.crypto"></a>

### qubic.exports.crypto : [<code>Promise.&lt;Crypto&gt;</code>](#Crypto)
> A promise which always resolves to object with crypto functions.


<br><a name="module_qubic.client"></a>

### qubic.client(options) ⇒ [<code>Client</code>](#Client)
**Emits**: [<code>info</code>](#Connection+event_info), [<code>open</code>](#Connection+event_open), [<code>close</code>](#Connection+event_close), [<code>error</code>](#Connection+event_error), [<code>inclusion</code>](#Client+event_inclusion), [<code>rejection</code>](#Client+event_rejection)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| options | <code>object</code> |  | Client options. |
| options.seed | <code>string</code> |  | Seed in 55 lowercase latin chars. |
| [options.index] | <code>number</code> | <code>0</code> | Identity index. |
| [options.connection] | [<code>Connection</code>](#Connection) |  | Client connection. |
| [options.computors] | <code>Array.&lt;object&gt;</code> |  | Specifies 3 computors to connect to, and with what options. Ignored when connection option is used. |
| options.computors[].url | <code>string</code> |  | Computor url. |
| [options.computors[].options] | <code>object</code> |  | WebSocket options. |
| [options.synchronizationInterval] | <code>number</code> |  | If no new tick appears after this interval an info event is emitted with updated sync status. Ignored when connection option is used. |
| [options.adminPublicKey] | <code>string</code> |  | Admin public key, for verification of current epoch and tick which are signed by admin. Ignored when connection option is used. |
| [options.reconnectTimeoutDuration] | <code>number</code> | <code>100</code> | Reconnect timeout duration. Ignored when connection option is used. |
| [options.db] | <code>object</code> |  | Database implementing the [level interface](https://github.com/Level/level), for storing transactions. |
| [options.dbPath] | <code>string</code> |  | Database path. |

**Example**  
```js
import qubic from 'qubic-js';

const client = qubic.client({
  seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
  computors: [
    { url: 'wss://AA.computor.com' },
    { url: 'wss://AB.computor.com' },
    { url: 'wss://AC.computor.com' },
  ],
  synchronizationInterval: 60 * 1000,
  adminPublicKey: '97CC65D1E59351EEFC776BCFF197533F148A8105DA84129C051F70DD9CA0FF82',
});

client.addListener('error', function (error) {
  console.log(error.message);
});
client.addListener('info', console.log);
```

<br><a name="module_qubic.connection"></a>

### qubic.connection(params) ⇒ [<code>Connection</code>](#Connection)
**Emits**: [<code>info</code>](#Connection+event_info), [<code>open</code>](#Connection+event_open), [<code>close</code>](#Connection+event_close), [<code>error</code>](#Connection+event_error)  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| params | <code>object</code> |  | Connection params. |
| params.computors | <code>Array.&lt;object&gt;</code> |  | Specifies 3 computors to connect to, and with what options. |
| params.computors[].url | <code>string</code> |  | Computor url. |
| [params.computors[].options] | <code>object</code> |  | WebSocket options. Node.js only. |
| params.synchronizationInterval | <code>number</code> |  | If no new tick appears after this interval an info event is emitted with updated sync status. |
| params.adminPublicKey | <code>string</code> |  | Admin public key, for verification of current epoch and tick which are signed by admin. |
| [params.reconnectTimeoutDuration] | <code>number</code> | <code>100</code> | Reconnect timeout duration. |

**Example**  
```js
import qubic from 'qubic-js';

const connection = qubic.connection({
  computors: [
    { url: 'wss://AA.computor.com' },
    { url: 'wss://AB.computor.com' },
    { url: 'wss://AC.computor.com' },
  ],
  synchronizationInterval: 60 * 1000,
  adminPublicKey: '97CC65D1E59351EEFC776BCFF197533F148A8105DA84129C051F70DD9CA0FF82',
});

connection.addListener('error', function (error) {
  console.log(error.message);
});
connection.addListener('info', console.log);
```

<br><a name="module_qubic.privateKey"></a>

### qubic.privateKey(seed, index, K12) ⇒ <code>Uint8Array</code>
> Generates a private key from seed.

**Returns**: <code>Uint8Array</code> - Private key bytes.  

| Param | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |
| index | <code>number</code> | Identity index. |
| K12 | [<code>K12</code>](#Crypto.K12) | K12 function. |


<br><a name="module_qubic.identity"></a>

### qubic.identity(seed, index) ⇒ <code>Promise.&lt;string&gt;</code>
> Creates an identity with checksum.

**Returns**: <code>Promise.&lt;string&gt;</code> - Identity with checksum in uppercase hex.  

| Param | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |
| index | <code>number</code> | Identity index. |


<br><a name="module_qubic.verifyChecksum"></a>

### qubic.verifyChecksum(identity) ⇒ <code>Promise.&lt;boolean&gt;</code>
> Validates integrity of identity with checksum.


| Param | Type | Description |
| --- | --- | --- |
| identity | <code>string</code> | Identity in uppercase hex. |


<br><a name="module_qubic.seedChecksum"></a>

### qubic.seedChecksum(seed) ⇒ <code>Promise.&lt;string&gt;</code>
**Returns**: <code>Promise.&lt;string&gt;</code> - Seed checksum in uppercase hex.  

| Param | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |


<br><a name="module_qubic.transaction"></a>

### qubic.transaction(params) ⇒ [<code>Promise.&lt;Transaction&gt;</code>](#Transaction)
> Creates a transaction which includes a transfer of energy between 2 entities,
> or an effect, or both. Transaction is atomic, meaaning that both transfer and
> effect will be proccessed or none.


| Param | Type |
| --- | --- |
| params | [<code>TransferParams</code>](#TransferParams), [<code>EffectParams</code>](#EffectParams), [<code>TransferAndEffectParams</code>](#TransferAndEffectParams) | 

**Example**  
```js
import qubic from 'qubic-js';

qubic
  .transaction({
    seed: 'vmscmtbcqjbqyqcckegsfdsrcgjpeejobolmimgorsqwgupzhkevreu',
    senderIdentity: 'DCMJGMELMPBOJCCOFAICMJCBKENNOPEJCLIPBKKKDKLDOMKFBPOFHFLGAHLNAFMKMHHOAE',
    index: 1337,
    identityNonce: 0,
    recipientIdentity: 'BPFJANADOGBDLNNONDILEMAICAKMEEGBFPJBKPBCEDFJIALDONODMAIMDBFKCFEEMEOLFK',
    energy: qubic.energy(1),
  })
  .then(function (transaction) {
    console.log(transaction);
  })
  .catch(function (error) {
    console.log(error.message);
  });
```

<br><a name="Client"></a>

## Client
**Mixes**: [<code>Connection</code>](#Connection)  

* [Client](#Client)
    * _instance_
        * ["inclusion"](#Client+event_inclusion)
        * ["rejection"](#Client+event_rejection)
    * _static_
        * [.identity](#Client.identity) : <code>string</code>
        * [.transaction(params)](#Client.transaction) ⇒ [<code>Transaction</code>](#Transaction)
        * [.addEnvironmentListener(environment, listener)](#Client.addEnvironmentListener)
        * [.removeEnvironmentListener(environment, listener)](#Client.removeEnvironmentListener)
        * [.terminate([options])](#Client.terminate)
        * [.launch()](#Client.launch)
        * [.close()](#Client.close)
        * [.sendCommand(command, payload)](#Client.sendCommand) ⇒ <code>Promise.&lt;object&gt;</code> \| <code>EventEmitter</code> \| <code>void</code>
        * [.setComputorUrl(index, url)](#Client.setComputorUrl)
        * [.open()](#Client.open)
        * [.computors()](#Client.computors) ⇒ <code>Array.&lt;string&gt;</code>


<br><a name="Client+event_inclusion"></a>

### "inclusion"
> Inclusion event.

**Properties**

| Name | Type | Description |
| --- | --- | --- |
| messageDigest | <code>string</code> | Hash of included transaction in uppercase hex. |
| epoch | <code>number</code> | Epoch at which transaction was included. |
| tick | <code>number</code> | Tick at which transaction was included. |


<br><a name="Client+event_rejection"></a>

### "rejection"
> Rejection event.

**Properties**

| Name | Type | Description |
| --- | --- | --- |
| messageDigest | <code>string</code> | Hash of rejected transaction in uppercase hex. |
| reason | <code>string</code> | Reason of rejection. |


<br><a name="Client.identity"></a>

### Client.identity : <code>string</code>
> Client identity in uppercase hex.


<br><a name="Client.transaction"></a>

### Client.transaction(params) ⇒ [<code>Transaction</code>](#Transaction)
> Creates a transaction which includes a transfer of energy between 2 entities,
> or an effect, or both. Transaction is atomic, meaaning that both transfer and
> effect will be proccessed or none.
> 
> Transactions are stored in database and their inclusion or rejection are monitored.

**Returns**: [<code>Transaction</code>](#Transaction) - Transaction object.  

| Param | Type | Description |
| --- | --- | --- |
| params | <code>object</code> |  |
| params.recipientIdentity | <code>string</code> | Recipient identity in uppercase hex. |
| params.energy | <code>bigint</code> | Transferred energy to recipient identity. |
| params.effectPayload | <code>TypedArray</code> | Effect payload. |


<br><a name="Client.addEnvironmentListener"></a>

### Client.addEnvironmentListener(environment, listener)
> Subcribes to an environment.


| Param | Type | Description |
| --- | --- | --- |
| environment | <code>string</code> | Environment hash. |
| listener | <code>function</code> |  |

**Example**  
```js
const listener = function (data) {
  console.log(data);
};

client.addEvironmentListener(
  'BPFJANADOGBDLNNONDILEMAICAKMEEGBFPJBKPBCEDFJIALDONODMAIMDBFKCFEE',
  listener
);
```

<br><a name="Client.removeEnvironmentListener"></a>

### Client.removeEnvironmentListener(environment, listener)
> Unsubscribes from an environment.


| Param | Type | Description |
| --- | --- | --- |
| environment | <code>string</code> | Environment hash. |
| listener | <code>function</code> |  |


<br><a name="Client.terminate"></a>

### Client.terminate([options])
> Closes database and connections to computors.


| Param | Type | Default |
| --- | --- | --- |
| [options] | <code>object</code> |  | 
| [options.closeConnection] | <code>boolean</code> | <code>true</code> | 


<br><a name="Client.launch"></a>

### Client.launch()
> Launches client by opening database and connections to computors.

**Emits**: [<code>info</code>](#Connection+event_info), [<code>open</code>](#Connection+event_open), [<code>close</code>](#Connection+event_close), [<code>error</code>](#Connection+event_error), [<code>inclusion</code>](#Client+event_inclusion), [<code>rejection</code>](#Client+event_rejection)  

<br><a name="Client.close"></a>

### Client.close()
> Terminates all 3 WebSocket connections.

**Mixes**: [<code>close</code>](#Connection.close)  

<br><a name="Client.sendCommand"></a>

### Client.sendCommand(command, payload) ⇒ <code>Promise.&lt;object&gt;</code> \| <code>EventEmitter</code> \| <code>void</code>
> Sends a client command to each connected computor, and compares responses before resolving.
> Available client commands:
> 
> | Command | Request | Response | Description |
> | --- | --- | --- | --- |
> | `1` | `{ identity }` | `{ identity, identityNonce }` | Fetches `identityNonce`. |
> | `2` | `{ identity }` | `{ identity, energy }` | Fetches `energy`. |
> | `3` | `{ message, signature }` | `void` | Sends a transaction with `base64`-encoded `message` & `signature` fields. |
> | `4` | `{ messageDigest }` | `{ messageDigest, inclusionState, tick, epoch }` or `{ messageDigest, reason }` | Fetches status of a transaction. Rejects with reason in case identity nonce has been overwritten. |
> | `5` | `{ environmentDigest }` | `{ environmentDigest, epoch, tick, data }` | Subscribes to an environment by its digest. |
> | `6` | `{ environmentDigest }` | `{ environmentDigest }` | Cancels environment subscription. |

**Mixes**: [<code>sendCommand</code>](#Connection.sendCommand)  

| Param | Type | Description |
| --- | --- | --- |
| command | <code>number</code> | Command index, must be an integer. |
| payload | <code>object</code> | Request payload. |


<br><a name="Client.setComputorUrl"></a>

### Client.setComputorUrl(index, url)
> Sets one of the 3 computors url each time.

**Mixes**: [<code>setComputorUrl</code>](#Connection.setComputorUrl)  

| Param | Type | Description |
| --- | --- | --- |
| index | <code>number</code> | Index of computor connection, 0, 1 or 2. |
| url | <code>string</code> | Computor url. |


<br><a name="Client.open"></a>

### Client.open()
> Opens all 3 WebSocket connections.

**Mixes**: [<code>open</code>](#Connection.open)  
**Emits**: [<code>info</code>](#Connection+event_info), [<code>open</code>](#Connection+event_open), [<code>close</code>](#Connection+event_close), [<code>error</code>](#Connection+event_error)  

<br><a name="Client.computors"></a>

### Client.computors() ⇒ <code>Array.&lt;string&gt;</code>
**Mixes**: [<code>computors</code>](#Connection.computors)  
**Returns**: <code>Array.&lt;string&gt;</code> - Array of computor urls.  

<br><a name="Connection"></a>

## Connection

* [Connection](#Connection)
    * _instance_
        * ["info"](#Connection+event_info)
        * ["open" (event)](#Connection+event_open)
        * ["error" (event)](#Connection+event_error)
        * ["close" (event)](#Connection+event_close)
    * _static_
        * [.close()](#Connection.close)
        * [.sendCommand(command, payload)](#Connection.sendCommand) ⇒ <code>Promise.&lt;object&gt;</code> \| <code>EventEmitter</code> \| <code>void</code>
        * [.setComputorUrl(index, url)](#Connection.setComputorUrl)
        * [.open()](#Connection.open)
        * [.computors()](#Connection.computors) ⇒ <code>Array.&lt;string&gt;</code>


<br><a name="Connection+event_info"></a>

### "info"
> Info event.

**Properties**

| Name | Type | Description |
| --- | --- | --- |
| syncStatus | <code>number</code> | Indicates which of the 3 computors have provided the same tick and epoch. 0 when offline, 3 when fully synced. |
| epoch | <code>number</code> | Current epoch. |
| tick | <code>number</code> | Current tick. |


<br><a name="Connection+event_open"></a>

### "open" (event)
> Open event. Emitted when a WebSocket connection opens.


| Param | Type | Description |
| --- | --- | --- |
| event | <code>event</code> | WebSocket event. |


<br><a name="Connection+event_error"></a>

### "error" (event)
> Error event. Emitted when a WebSocket connection errors.


| Param | Type | Description |
| --- | --- | --- |
| event | <code>event</code> | WebSocket event. |


<br><a name="Connection+event_close"></a>

### "close" (event)
> Close event. Emitted when a WebSocket connection closes.


| Param | Type | Description |
| --- | --- | --- |
| event | <code>event</code> | WebSocket event. |


<br><a name="Connection.close"></a>

### Connection.close()
> Terminates all 3 WebSocket connections.


<br><a name="Connection.sendCommand"></a>

### Connection.sendCommand(command, payload) ⇒ <code>Promise.&lt;object&gt;</code> \| <code>EventEmitter</code> \| <code>void</code>
> Sends a client command to each connected computor, and compares responses before resolving.
> Available client commands:
> 
> | Command | Request | Response | Description |
> | --- | --- | --- | --- |
> | `1` | `{ identity }` | `{ identity, identityNonce }` | Fetches `identityNonce`. |
> | `2` | `{ identity }` | `{ identity, energy }` | Fetches `energy`. |
> | `3` | `{ message, signature }` | `void` | Sends a transaction with `base64`-encoded `message` & `signature` fields. |
> | `4` | `{ messageDigest }` | `{ messageDigest, inclusionState, tick, epoch }` or `{ messageDigest, reason }` | Fetches status of a transaction. Rejects with reason in case identity nonce has been overwritten. |
> | `5` | `{ environmentDigest }` | `{ environmentDigest, epoch, tick, data }` | Subscribes to an environment by its digest. |
> | `6` | `{ environmentDigest }` | `{ environmentDigest }` | Cancels environment subscription. |


| Param | Type | Description |
| --- | --- | --- |
| command | <code>number</code> | Command index, must be an integer. |
| payload | <code>object</code> | Request payload. |


<br><a name="Connection.setComputorUrl"></a>

### Connection.setComputorUrl(index, url)
> Sets one of the 3 computors url each time.


| Param | Type | Description |
| --- | --- | --- |
| index | <code>number</code> | Index of computor connection, 0, 1 or 2. |
| url | <code>string</code> | Computor url. |


<br><a name="Connection.open"></a>

### Connection.open()
> Opens all 3 WebSocket connections.

**Emits**: [<code>info</code>](#Connection+event_info), [<code>open</code>](#Connection+event_open), [<code>close</code>](#Connection+event_close), [<code>error</code>](#Connection+event_error)  

<br><a name="Connection.computors"></a>

### Connection.computors() ⇒ <code>Array.&lt;string&gt;</code>
**Returns**: <code>Array.&lt;string&gt;</code> - Array of computor urls.  

<br><a name="Crypto"></a>

## Crypto : <code>object</code>

* [Crypto](#Crypto) : <code>object</code>
    * [.schnorrq](#Crypto.schnorrq) : <code>object</code>
        * [.generatePublicKey(secretKey)](#Crypto.schnorrq.generatePublicKey) ⇒ <code>Uint8Array</code>
        * [.sign(secretKey, publicKey, message)](#Crypto.schnorrq.sign) ⇒ <code>Uint8Array</code>
        * [.verify(publicKey, message, signature)](#Crypto.schnorrq.verify) ⇒ <code>number</code>
    * [.kex](#Crypto.kex) : <code>object</code>
        * [.generateCompressedPublicKey(secretKey)](#Crypto.kex.generateCompressedPublicKey) ⇒ <code>Uint8Array</code>
        * [.compressedSecretAgreement(secretKey, publicKey)](#Crypto.kex.compressedSecretAgreement) ⇒ <code>Uint8Array</code>
    * [.K12(input, output, outputLength, outputOffset)](#Crypto.K12)


<br><a name="Crypto.schnorrq"></a>

### Crypto.schnorrq : <code>object</code>

* [.schnorrq](#Crypto.schnorrq) : <code>object</code>
    * [.generatePublicKey(secretKey)](#Crypto.schnorrq.generatePublicKey) ⇒ <code>Uint8Array</code>
    * [.sign(secretKey, publicKey, message)](#Crypto.schnorrq.sign) ⇒ <code>Uint8Array</code>
    * [.verify(publicKey, message, signature)](#Crypto.schnorrq.verify) ⇒ <code>number</code>


<br><a name="Crypto.schnorrq.generatePublicKey"></a>

#### schnorrq.generatePublicKey(secretKey) ⇒ <code>Uint8Array</code>

| Param | Type |
| --- | --- |
| secretKey | <code>Uint8Array</code> | 


<br><a name="Crypto.schnorrq.sign"></a>

#### schnorrq.sign(secretKey, publicKey, message) ⇒ <code>Uint8Array</code>

| Param | Type |
| --- | --- |
| secretKey | <code>Uint8Array</code> | 
| publicKey | <code>Uint8Array</code> | 
| message | <code>Uint8Array</code> | 


<br><a name="Crypto.schnorrq.verify"></a>

#### schnorrq.verify(publicKey, message, signature) ⇒ <code>number</code>
**Returns**: <code>number</code> - 1 if valid, 0 if invalid  

| Param | Type |
| --- | --- |
| publicKey | <code>Uint8Array</code> | 
| message | <code>Uint8Array</code> | 
| signature | <code>Uint8Array</code> | 


<br><a name="Crypto.kex"></a>

### Crypto.kex : <code>object</code>

* [.kex](#Crypto.kex) : <code>object</code>
    * [.generateCompressedPublicKey(secretKey)](#Crypto.kex.generateCompressedPublicKey) ⇒ <code>Uint8Array</code>
    * [.compressedSecretAgreement(secretKey, publicKey)](#Crypto.kex.compressedSecretAgreement) ⇒ <code>Uint8Array</code>


<br><a name="Crypto.kex.generateCompressedPublicKey"></a>

#### kex.generateCompressedPublicKey(secretKey) ⇒ <code>Uint8Array</code>
**Returns**: <code>Uint8Array</code> - Public key  

| Param | Type |
| --- | --- |
| secretKey | <code>Uint8Array</code> | 


<br><a name="Crypto.kex.compressedSecretAgreement"></a>

#### kex.compressedSecretAgreement(secretKey, publicKey) ⇒ <code>Uint8Array</code>
**Returns**: <code>Uint8Array</code> - Shared key  

| Param | Type |
| --- | --- |
| secretKey | <code>Uint8Array</code> | 
| publicKey | <code>Uint8Array</code> | 


<br><a name="Crypto.K12"></a>

### Crypto.K12(input, output, outputLength, outputOffset)

| Param | Type | Default |
| --- | --- | --- |
| input | <code>Uint8Array</code> |  | 
| output | <code>Uint8Array</code> |  | 
| outputLength | <code>number</code> |  | 
| outputOffset | <code>number</code> | <code>0</code> | 


<br><a name="TransferParams"></a>

## TransferParams : <code>object</code>
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |
| index | <code>number</code> | Index of private key which was used to derive sender identity. |
| senderIdentity | <code>string</code> | Sender identity in uppercase hex. |
| identityNonce | <code>number</code> | Identity nonce. |
| energy | <code>bigint</code> | Transferred energy to recipient identity. |
| recipientIdentity | <code>string</code> | Recipient identity in uppercase hex. |


<br><a name="EffectParams"></a>

## EffectParams : <code>object</code>
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |
| index | <code>number</code> | Index of private key which was used to derive sender identity. |
| senderIdentity | <code>string</code> | Sender identity in uppercase hex. |
| identityNonce | <code>number</code> | Identity nonce. |
| effectPayload | <code>Uint8Array</code> | Effect payload |


<br><a name="TransferAndEffectParams"></a>

## TransferAndEffectParams : <code>object</code>
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| seed | <code>string</code> | Seed in 55 lowercase latin chars. |
| index | <code>number</code> | Index of private key which was used to derive sender identity. |
| senderIdentity | <code>string</code> | Sender identity in shifted uppercase hex. |
| identityNonce | <code>number</code> | Identity nonce. |
| energy | <code>bigint</code> | Transferred energy to recipient identity. |
| recipientIdentity | <code>string</code> | Recipient identity in shifted uppercase hex. |
| effectPayload | <code>Uint8Array</code> | Effect payload |


<br><a name="Transaction"></a>

## Transaction : <code>object</code>
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| hash | <code>string</code> | Transaction hash in shifted uppercase hex. |
| message | <code>string</code> | Base64-encoded signed message. |
| signature | <code>string</code> | Base64-encoded signature. |

