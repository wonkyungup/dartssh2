import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import 'package:dartssh2/src/utils/cipher_ext.dart';

/// Packet-level symmetric cipher used by [SSHTransport] (CTR / CBC).
///
/// Unlike pointycastle's [BlockCipher], data is processed a whole packet at a
/// time so that native implementations pay one call per packet instead of one
/// per 16-byte block. State (CTR counter, CBC chaining) carries over between
/// calls exactly like the block cipher it replaces.
abstract class SSHPacketCipher {
  int get blockSize;

  /// Encrypts or decrypts [data]. `data.length` must be a multiple of
  /// [blockSize].
  Uint8List process(Uint8List data);
}

/// Packet-level MAC used by [SSHTransport]. One [update]..[finish] round per
/// packet; [finish] resets the state for the next packet.
abstract class SSHPacketMac {
  int get macSize;

  void update(Uint8List data);

  Uint8List finish();
}

/// Supplies faster (e.g. OS-provided) implementations of the transport ciphers
/// and MACs. Return `null` for anything not supported; the pure-Dart
/// implementation is used instead.
///
/// Objects are never disposed explicitly (a packet may still be in flight when
/// the transport closes); native implementations should free their memory
/// with a `NativeFinalizer`.
abstract class SSHCryptoProvider {
  SSHPacketCipher? createCipher(
    String algorithm,
    Uint8List key,
    Uint8List iv, {
    required bool forEncryption,
  });

  SSHPacketMac? createMac(String algorithm, Uint8List key);
}

/// Global hook for [SSHCryptoProvider].
///
/// Static state is per isolate: set [provider] in every isolate that opens
/// SSH connections, before connecting. Changing it only affects keys derived
/// afterwards (new connections and re-keys).
class SSHCrypto {
  SSHCrypto._();

  static SSHCryptoProvider? provider;
}

/// Pure-Dart fallback wrapping a pointycastle [BlockCipher].
class BlockSSHPacketCipher extends SSHPacketCipher {
  BlockSSHPacketCipher(this.cipher);

  final BlockCipher cipher;

  @override
  int get blockSize => cipher.blockSize;

  @override
  Uint8List process(Uint8List data) => cipher.processAll(data);
}

/// Pure-Dart fallback wrapping a pointycastle [Mac].
class PointycastleSSHPacketMac extends SSHPacketMac {
  PointycastleSSHPacketMac(this.mac);

  final Mac mac;

  @override
  int get macSize => mac.macSize;

  @override
  void update(Uint8List data) => mac.updateAll(data);

  @override
  Uint8List finish() => mac.finish();
}
