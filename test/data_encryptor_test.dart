import 'dart:convert';
import 'dart:math';

import 'package:faker/faker.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:data_encryptor/data_encryptor.dart';

void main() {
  group('DataEncryptor', () {
    late String base64Key;
    late DataEncryptor dataEncryptor;

    setUp(() {
      base64Key = base64Encode(
        Uint8List.fromList(
          List.generate(16, (_) => Random.secure().nextInt(255)),
        ),
      );

      dataEncryptor = DataEncryptor(
        secret: base64Key,
        keyType: DataEncryptorKeyType.base64,
        padding: null,
      );
    });

    test('encrypt should return a non-null base64 encoded string', () {
      final plainText = faker.lorem.sentence();
      final encryptedText = dataEncryptor.encrypt(plainText);
      expect(encryptedText, isNotNull);
      expect(encryptedText, isA<String>());
    });

    test('decrypt should return the original string after encryption', () {
      final plainText = faker.lorem.sentence();

      final encryptedText = dataEncryptor.encrypt(plainText);
      final decryptedText = dataEncryptor.decrypt(encryptedText);
      expect(decryptedText, equals(plainText));
    });

    test('encrypting the same text with different IVs should produce different outputs', () {
      final plainText = faker.lorem.sentence();
      final encryptedText1 = dataEncryptor.encrypt(plainText);
      final encryptedText2 = dataEncryptor.encrypt(plainText);

      expect(
        encryptedText1,
        isNot(equals(encryptedText2)),
        reason: "Encrypted texts should differ with different IVs",
      );
    });

    test('decrypt with invalid base64 should throw FormatException', () {
      expect(() => dataEncryptor.decrypt("invalidBase64"), throwsA(isA<FormatException>()));
    });

    test('decrypt should return the original string after encryption', () {
      dataEncryptor = DataEncryptor(
        keyType: DataEncryptorKeyType.base64,
        secret: '/vobL2F70uB8n2K+5KyFfg==',
        padding: null,
      );

      const originalString =
          '{"number":"1234567890","holder":"John Doe","expiration_month":"12","expiration_year":"2023","cvv":"123"}';
      const encryptedString =
          'MjFhYmRmNWQyNDQyNzM0NDk2ZDhmZGRmOTg0YmRiNGY6ZGE3ZDRmNTk1NmU5OGM0OWM1ODUzZTk0NTE0OGY2ODJmNDY0YThhOTEyZjIwZTFhZDgxYWI4ZDY1M2NiYWNkZGI4NDk3ZGYwZTZmNzdhOWIyOGJjOTUwNGZkYmJhZGQ2MGZjMWVmNmU1YjQzMjA2MDRhMjIyMjcyNDJiY2E3NWE0ZDNmOTVhOGI1MjBhNmMzMDhiOTUzNTFjNjJkZTNiYTI4MDA1MzE1ZWMyNjZiMzA0MTZjN2JkMzE4ZTYwYWU5MDdmZjA3ZmZmZTA5NTQ1Ng==';
      final decrypted = dataEncryptor.decrypt(encryptedString);

      expect(decrypted, equals(originalString));
    });
  });
}
