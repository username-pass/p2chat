class CryptoHelper {
  async signMessage(message, privateKey) {
    try {
      const signature = await crypto.subtle.sign(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" },
        },
        privateKey,
        new TextEncoder().encode(message)
      );

      return signature;
    } catch (error) {
      console.error("Error signing message:", error);
    }
  }

  async verifySignature(message, signature, publicKey) {
    try {
      const isVerified = await crypto.subtle.verify(
        {
          name: "ECDSA",
          hash: { name: "SHA-256" },
        },
        publicKey,
        signature,
        new TextEncoder().encode(message)
      );

      return isVerified;
    } catch (error) {
      console.error("Error verifying signature:", error);
    }
  }
  async generateHMACKey(password, salt) {
    try {
      const passwordBuffer = new TextEncoder().encode(password);
      const saltBuffer = new TextEncoder().encode(salt);

      const importedKey = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
      );

      const derivedKey = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: 100000,
          hash: "SHA-256",
        },
        importedKey,
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign", "verify"]
      );

      return derivedKey;
    } catch (error) {
      console.error("Error generating HMAC key:", error);
    }
  }

  async encrypt(data, key) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        key,
        new TextEncoder().encode(data)
      );

      return { iv: iv, data: new Uint8Array(encryptedData) };
    } catch (error) {
      console.error("Error encrypting data:", error);
    }
  }

  async decrypt(encryptedData, key) {
    try {
      const decryptedData = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: encryptedData.iv,
        },
        key,
        encryptedData.data
      );

      return new TextDecoder().decode(decryptedData);
    } catch (error) {
      console.error("Error decrypting data:", error);
    }
  }
  async generateKeyPair() {
    try {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: "ECDSA",
          namedCurve: "P-256",
        },
        true,
        ["sign", "verify"]
      );

      return keyPair;
    } catch (error) {
      console.error("Error generating key pair:", error);
    }
  }
  async exportPublicKey(keyPair) {
    try {
      const publicKey = await crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      return publicKey;
    } catch (error) {
      console.error("Error exporting public key:", error);
    }
  }
  async importPublicKey(publicKey) {
    try {
      const importedKey = await crypto.subtle.importKey(
        "spki",
        publicKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );

      return importedKey;
    } catch (error) {
      console.error("Error importing public key:", error);
    }
  }
  async exportPublicKeyAsString(keyPair) {
    try {
      const publicKey = await crypto.subtle.exportKey(
        "spki",
        keyPair.publicKey
      );
      const publicKeyString = this.arrayBufferToBase64(publicKey);

      return publicKeyString;
    } catch (error) {
      console.error("Error exporting public key:", error);
    }
  }
  arrayBufferToBase64(buffer) {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    return btoa(binary);
  }
}

(async () => {
  const cryptoHelper = new CryptoHelper();
  const password = "yourPassword";
  const salt = Crypto.getRandomValues(new Uint8Array(16));
  const hmacKey = await cryptoHelper.generateHMACKey(password, salt);
  const keyPair = await cryptoHelper.generateKeyPair();
  console.log("hello");

  const publicKeyString = await cryptoHelper.exportPublicKeyAsString(keyPair);
  console.log("Public Key as String:", publicKeyString);
  const dataToEncrypt = "Hello, encrypted world!";
  const encryptedData = await cryptoHelper.encrypt(dataToEncrypt, hmacKey);
  console.log("Encrypted Data:", encryptedData);

  const decryptedData = await cryptoHelper.decrypt(encryptedData, hmacKey);
  console.log("Decrypted Data:", decryptedData);
})();
