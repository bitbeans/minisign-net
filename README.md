# Minisign.Net 

![.NET Core](https://github.com/bitbeans/minisign-net/workflows/.NET%20Core/badge.svg)

Minisign.Net is a .NET port of [minisign](https://github.com/jedisct1/minisign) written by @jedisct1 Frank Denis. If you are looking for a command line tool, please use the [original minisign software](https://jedisct1.github.io/minisign/). There are pre-compiled versions for any os.

[minisign](https://github.com/jedisct1/minisign/blob/master/LICENSE) Copyright (c) 2015 - 2017 Frank Denis 

## Available Methods

### Sign a file
```csharp
public static string Sign(string fileToSign, MinisignPrivateKey minisignPrivateKey, string untrustedComment = "", string trustedComment = "", string outputFolder = "")
```

### Validate a file
```csharp
public static bool ValidateSignature(string filePath, MinisignSignature signature, MinisignPublicKey publicKey)

public static bool ValidateSignature(byte[] message, MinisignSignature signature, MinisignPublicKey publicKey)
```

### Generate a key pair
```csharp
public static MinisignKeyPair GenerateKeyPair(string password, bool writeOutputFiles = false, string outputFolder = "", string keyPairFileName = "minisign")
```

### Load a signature
```csharp
public static MinisignSignature LoadSignatureFromString(string signatureString, string trustedComment, string globalSignature)

public static MinisignSignature LoadSignatureFromFile(string signatureFile)

public static MinisignSignature LoadSignature(byte[] signature, byte[] trustedComment, byte[] globalSignature)
```

### Load a public key
```csharp
public static MinisignPublicKey LoadPublicKeyFromString(string publicKeyString)

public static MinisignPublicKey LoadPublicKeyFromFile(string publicKeyFile)

public static MinisignPublicKey LoadPublicKey(byte[] publicKey)
```

### Load a private key
```csharp
public static MinisignPrivateKey LoadPrivateKeyFromString(string privateKeyString, string password)

public static MinisignPrivateKey LoadPrivateKeyFromFile(string privateKeyFile, string password)

public static MinisignPrivateKey LoadPrivateKey(byte[] privateKey, byte[] password)
```


## License
[MIT](https://en.wikipedia.org/wiki/MIT_License)