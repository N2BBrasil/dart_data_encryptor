# Data Encryptor

A Flutter package that provides a simple and secure way to encrypt and decrypt data using AES encryption.

## Features

- 🔒 AES encryption with CTR mode
- 🔑 Multiple key type support (Base64, Base16, UTF8)
- 🛡️ Secure IV (Initialization Vector) handling
- 📦 Easy to use API
- 🎯 Null safety support

## Installation

Add this to your package's `pubspec.yaml` file:

```yaml
dependencies:
  data_encryptor: ^1.0.0
```

## Usage

### Basic Usage

```dart
import 'package:data_encryptor/data_encryptor.dart';

void main() {
  // Create an instance with a secret key
  final encryptor = DataEncryptor(
    secret: 'your-secret-key-here',
    keyType: DataEncryptorKeyType.utf8,
  );

  // Encrypt data
  final encrypted = encryptor.encrypt('Hello, World!');
  print('Encrypted: $encrypted');

  // Decrypt data
  final decrypted = encryptor.decrypt(encrypted);
  print('Decrypted: $decrypted'); // Output: Hello, World!
}
```

### Key Types

The package supports three types of key formats:

1. `DataEncryptorKeyType.base64`: For Base64 encoded keys
2. `DataEncryptorKeyType.base16`: For hexadecimal encoded keys
3. `DataEncryptorKeyType.utf8`: For UTF-8 encoded keys

### Custom Padding

You can specify custom padding when creating the encryptor:

```dart
final encryptor = DataEncryptor(
  secret: 'your-secret-key-here',
  keyType: DataEncryptorKeyType.utf8,
  padding: 'PKCS7',
);
```

## Security Considerations

- Always store your secret keys securely
- Use strong, randomly generated keys
- Keep your keys private and never commit them to version control
- Consider using environment variables or secure storage solutions for key management

## Requirements

- Dart SDK: ^3.5.1
- Flutter: >=1.17.0

## Dependencies

- [encrypt](https://pub.dev/packages/encrypt): ^5.0.3
- [convert](https://pub.dev/packages/convert): ^3.1.1

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
