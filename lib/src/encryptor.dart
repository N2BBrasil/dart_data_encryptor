import 'dart:convert';

import 'package:convert/convert.dart' show hex;
import 'package:encrypt/encrypt.dart';

enum DataEncryptorKeyType {
  base64,
  base16,
  utf8,
}

class DataEncryptor {
  DataEncryptor({
    required String secret,
    required DataEncryptorKeyType keyType,
    String? padding,
  }) : _encrypter = _EncrypterInstance(keyType, secret: secret, padding: padding);

  final _EncrypterInstance _encrypter;

  @override
  String encrypt(String plainText) {
    final iv = IV.fromLength(16);
    final encryptedPlainText = _encrypter.encrypt(plainText, iv: iv);

    final value = [
      hex.encode(iv.bytes),
      hex.encode(encryptedPlainText.bytes),
    ].join(':');

    return utf8.fuse(base64).encode(value);
  }

  @override
  String decrypt(String value) {
    final parts = utf8.fuse(base64).decode(value).split(':');
    final iv = IV.fromBase16(parts[0]);
    final encryptedText = Encrypted.fromBase16(parts[1]);

    return _encrypter.decrypt(encryptedText, iv: iv);
  }
}

class _EncrypterInstance extends Encrypter {
  _EncrypterInstance._(
    Key key, {
    String? padding,
  }) : super(AES(key, mode: AESMode.ctr, padding: padding));

  _EncrypterInstance._fromBase64(
    String base64Key,
    String? padding,
  ) : this._(Key.fromBase64(base64Key), padding: padding);

  _EncrypterInstance._fromBase16(
    String base16Key,
    String? padding,
  ) : this._(Key.fromBase16(base16Key), padding: padding);

  _EncrypterInstance._fromUtf8(
    String utf8Key,
    String? padding,
  ) : this._(Key.fromUtf8(utf8Key), padding: padding);

  factory _EncrypterInstance(
    DataEncryptorKeyType keyType, {
    required String secret,
    required String? padding,
  }) {
    return switch (keyType) {
      DataEncryptorKeyType.base64 => _EncrypterInstance._fromBase64(secret, padding),
      DataEncryptorKeyType.base16 => _EncrypterInstance._fromBase16(secret, padding),
      DataEncryptorKeyType.utf8 => _EncrypterInstance._fromUtf8(secret, padding),
    };
  }
}
