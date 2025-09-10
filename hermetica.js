/**
 * RSA Encryption/Decryption usando Web Crypto API
 * Implementazione per browser con crypto.subtle
 */

class WebCryptoRSA {
  constructor() {
    this.keyPair = null;
    this.keySize = 2048;
  }

  /**
   * Genera una nuova coppia di chiavi RSA
   * @param {number} keySize - Dimensione chiave in bit (default: 2048)
   * @returns {Promise<CryptoKeyPair>} Coppia di chiavi
   */
  async generateKeyPair(keySize = 2048) {
    try {
      console.log(`🔑 Generando coppia chiavi RSA ${keySize}-bit...`);
      
      this.keySize = keySize;
      
      // Genera chiavi usando Web Crypto API
      this.keyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: keySize,
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: "SHA-256"
        },
        true, // extractable
        ["encrypt", "decrypt"]
      );

      console.log("✅ Chiavi generate con successo!");
      console.log(`📏 Dimensione modulo: ${keySize} bit`);
      
      return this.keyPair;
      
    } catch (error) {
      console.error("❌ Errore generazione chiavi:", error);
      throw error;
    }
  }

  /**
   * Genera coppia di chiavi per firma digitale
   * @param {number} keySize - Dimensione chiave in bit (default: 2048)
   * @returns {Promise<CryptoKeyPair>} Coppia di chiavi per firma
   */
  async generateSigningKeyPair(keySize = 2048) {
    try {
      console.log(`🔑 Generando chiavi RSA per firma ${keySize}-bit...`);
      
      this.signingKeyPair = await crypto.subtle.generateKey(
        {
          name: "RSA-PSS",
          modulusLength: keySize,
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: "SHA-256"
        },
        true, // extractable
        ["sign", "verify"]
      );

      console.log("✅ Chiavi per firma generate con successo!");
      return this.signingKeyPair;
      
    } catch (error) {
      console.error("❌ Errore generazione chiavi firma:", error);
      throw error;
    }
  }

  /**
   * Cripta un messaggio usando la chiave pubblica
   * @param {string} plaintext - Testo in chiaro
   * @param {CryptoKey} publicKey - Chiave pubblica (opzionale)
   * @returns {Promise<string>} Messaggio crittografato (base64)
   */
  async encrypt(plaintext, publicKey = null) {
    try {
      const key = publicKey || this.keyPair.publicKey;
      if (!key) {
        throw new Error("Nessuna chiave pubblica disponibile");
      }

      // Calcola dimensione massima del messaggio
      const maxMessageLength = Math.floor(this.keySize / 8) - 42; // OAEP padding
      
      const plaintextBytes = new TextEncoder().encode(plaintext);
      if (plaintextBytes.length > maxMessageLength) {
        throw new Error(`Messaggio troppo lungo. Max ${maxMessageLength} bytes per chiave ${this.keySize}-bit`);
      }

      // Cripta usando RSA-OAEP con SHA-256
      const encrypted = await crypto.subtle.encrypt(
        {
          name: "RSA-OAEP"
        },
        key,
        plaintextBytes
      );

      const base64Result = this.arrayBufferToBase64(encrypted);
      
      console.log(`🔒 Messaggio crittografato: ${plaintext.length} → ${base64Result.length} caratteri`);
      return base64Result;
      
    } catch (error) {
      console.error("❌ Errore crittografia:", error);
      throw error;
    }
  }

  /**
   * Decripta un messaggio usando la chiave privata
   * @param {string} ciphertext - Messaggio crittografato (base64)
   * @param {CryptoKey} privateKey - Chiave privata (opzionale)
   * @returns {Promise<string>} Testo in chiaro
   */
  async decrypt(ciphertext, privateKey = null) {
    try {
      const key = privateKey || this.keyPair.privateKey;
      if (!key) {
        throw new Error("Nessuna chiave privata disponibile");
      }

      // Converte da base64 e decripta
      const encryptedBuffer = this.base64ToArrayBuffer(ciphertext);
      
      const decrypted = await crypto.subtle.decrypt(
        {
          name: "RSA-OAEP"
        },
        key,
        encryptedBuffer
      );

      const plaintext = new TextDecoder().decode(decrypted);
      
      console.log(`🔓 Messaggio decrittografato: ${ciphertext.length} → ${plaintext.length} caratteri`);
      return plaintext;
      
    } catch (error) {
      console.error("❌ Errore decrittografia:", error);
      throw error;
    }
  }

  /**
   * Firma un messaggio con la chiave privata
   * @param {string} message - Messaggio da firmare
   * @param {CryptoKey} privateKey - Chiave privata (opzionale)
   * @returns {Promise<string>} Firma digitale (base64)
   */
  async sign(message, privateKey = null) {
    try {
      const key = privateKey || (this.signingKeyPair && this.signingKeyPair.privateKey);
      if (!key) {
        throw new Error("Nessuna chiave privata per firma disponibile");
      }

      const messageBytes = new TextEncoder().encode(message);
      
      const signature = await crypto.subtle.sign(
        {
          name: "RSA-PSS",
          saltLength: 32 // SHA-256 digest length
        },
        key,
        messageBytes
      );

      const base64Signature = this.arrayBufferToBase64(signature);
      
      console.log(`✍️ Messaggio firmato: ${message.length} caratteri → firma ${base64Signature.length} caratteri`);
      return base64Signature;
      
    } catch (error) {
      console.error("❌ Errore firma:", error);
      throw error;
    }
  }

  /**
   * Verifica la firma di un messaggio
   * @param {string} message - Messaggio originale
   * @param {string} signature - Firma digitale (base64)
   * @param {CryptoKey} publicKey - Chiave pubblica (opzionale)
   * @returns {Promise<boolean>} True se la firma è valida
   */
  async verify(message, signature, publicKey = null) {
    try {
      const key = publicKey || (this.signingKeyPair && this.signingKeyPair.publicKey);
      if (!key) {
        throw new Error("Nessuna chiave pubblica per verifica disponibile");
      }

      const messageBytes = new TextEncoder().encode(message);
      const signatureBuffer = this.base64ToArrayBuffer(signature);
      
      const isValid = await crypto.subtle.verify(
        {
          name: "RSA-PSS",
          saltLength: 32 // SHA-256 digest length
        },
        key,
        signatureBuffer,
        messageBytes
      );

      console.log(`🔍 Verifica firma: ${isValid ? '✅ VALIDA' : '❌ INVALIDA'}`);
      return isValid;
      
    } catch (error) {
      console.error("❌ Errore verifica firma:", error);
      return false;
    }
  }
  
  async encryptLong(plaintext, publicKey = null) {
    try {
      const key = publicKey || (this.keyPair && this.keyPair.publicKey);
      if (!key) throw new Error("Nessuna chiave pubblica disponibile");

      // Ottieni modulo (in bit) dalla chiave se possibile
      const modulusBits = (key.algorithm && key.algorithm.modulusLength) ? key.algorithm.modulusLength : this.keySize;
      const keyBytes = Math.floor(modulusBits / 8);

      // Determina hash usata (fallback a SHA-256 se non disponibile)
      const hashName = (key.algorithm && key.algorithm.hash && key.algorithm.hash.name) ? key.algorithm.hash.name.toUpperCase() : 'SHA-256';

      const hashLenMap = { 'SHA-1': 20, 'SHA-256': 32, 'SHA-384': 48, 'SHA-512': 64 };
      const hLen = hashLenMap[hashName] || 32; // default SHA-256

      const oaepOverhead = 2 * hLen + 2;
      const maxChunkSize = keyBytes - oaepOverhead;
      if (maxChunkSize <= 0) throw new Error(`Key size troppo piccola per OAEP+${hashName} (keyBytes=${keyBytes})`);

      // Encodifica testo in bytes (una volta sola)
      const encoder = new TextEncoder();
      const plaintextBytes = encoder.encode(plaintext); // Uint8Array

      const chunks = [];
      for (let offset = 0; offset < plaintextBytes.length; offset += maxChunkSize) {
        const end = Math.min(offset + maxChunkSize, plaintextBytes.length);
        // subarray ritorna una vista corretta: passala direttamente a subtle.encrypt
        const chunkBytes = plaintextBytes.subarray(offset, end);

        // IMPORTANT: passiamo la TypedArray stessa (ArrayBufferView), non .buffer che potrebbe includere altri dati
        const encrypted = await crypto.subtle.encrypt(
          { name: "RSA-OAEP" },
          key,
          chunkBytes // ArrayBufferView è accettato e corretto
        );

        chunks.push(this.arrayBufferToBase64(encrypted));
      }

      console.log(`📦 Messaggio lungo diviso in ${chunks.length} blocchi (maxChunkSize=${maxChunkSize} bytes, hash=${hashName})`);
      return JSON.stringify(chunks);

    } catch (error) {
      console.error("❌ Errore crittografia lunga:", error);
      throw error;
    }
  }

  /**
   * Decripta messaggi lunghi ricostruendo dai blocchi
   * @param {string} encryptedChunks - Array di blocchi crittografati (JSON)
   * @param {CryptoKey} privateKey - Chiave privata (opzionale)
   * @returns {Promise<string>} Testo in chiaro ricostruito
   */
  async decryptLong(encryptedChunks, privateKey = null) {
    try {
      const chunks = JSON.parse(encryptedChunks);
      let plaintext = '';

      for (const chunk of chunks) {
        const decryptedChunk = await this.decrypt(chunk, privateKey);
        plaintext += decryptedChunk;
      }

      console.log(`📦 Ricostruito messaggio da ${chunks.length} blocchi`);
      return plaintext;
      
    } catch (error) {
      console.error("❌ Errore decrittografia lunga:", error);
      throw error;
    }
  }

  /**
   * Esporta la chiave pubblica in formato Base64 (senza PEM headers)
   * @param {CryptoKey} publicKey - Chiave pubblica (opzionale)
   * @returns {Promise<string>} Chiave pubblica in base64
   */
  async exportPublicKeyRaw(publicKey = null) {
    try {
      const key = publicKey || this.keyPair.publicKey;
      if (!key) {
        throw new Error("Nessuna chiave pubblica disponibile");
      }

      const exported = await crypto.subtle.exportKey("spki", key);
      const base64 = this.arrayBufferToBase64(exported);
      
      return base64;
    } catch (error) {
      console.error("❌ Errore esportazione chiave pubblica raw:", error);
      throw error;
    }
  }

  /**
   * Esporta la chiave pubblica in formato PEM (standard)
   * @param {CryptoKey} publicKey - Chiave pubblica (opzionale)
   * @returns {Promise<string>} Chiave pubblica in formato PEM
   */
  async exportPublicKey(publicKey = null) {
    try {
      const base64 = await this.exportPublicKeyRaw(publicKey);
      
      // Formatta come PEM per compatibilità standard
      const pem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
      
      return pem;
    } catch (error) {
      console.error("❌ Errore esportazione chiave pubblica:", error);
      throw error;
    }
  }

  /**
   * Importa una chiave pubblica da formato Base64 (senza PEM headers)
   * @param {string} base64Key - Chiave pubblica in base64
   * @returns {Promise<CryptoKey>} Chiave pubblica importata
   */
  async importPublicKeyRaw(base64Key) {
    try {
      const binaryKey = this.base64ToArrayBuffer(base64Key);
      
      const importedKey = await crypto.subtle.importKey(
        "spki",
        binaryKey,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["encrypt"]
      );

      return importedKey;
    } catch (error) {
      console.error("❌ Errore importazione chiave pubblica raw:", error);
      throw error;
    }
  }

  /**
   * Esporta la chiave privata in formato PEM
   * @param {CryptoKey} privateKey - Chiave privata (opzionale)
   * @returns {Promise<string>} Chiave privata in formato PEM
   */
  async exportPrivateKey(privateKey = null) {
    try {
      const key = privateKey || this.keyPair.privateKey;
      if (!key) {
        throw new Error("Nessuna chiave privata disponibile");
      }

      const exported = await crypto.subtle.exportKey("pkcs8", key);
      const base64 = this.arrayBufferToBase64(exported);
      
      // Formatta come PEM
      const pem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PRIVATE KEY-----`;
      
      return pem;
    } catch (error) {
      console.error("❌ Errore esportazione chiave privata:", error);
      throw error;
    }
  }

  /**
   * Importa una chiave pubblica da formato PEM
   * @param {string} pemKey - Chiave pubblica in formato PEM
   * @returns {Promise<CryptoKey>} Chiave pubblica importata
   */
  async importPublicKey(pemKey) {
    try {
      // Rimuovi header/footer PEM e spazi
      const base64 = pemKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');
      
      const binaryKey = this.base64ToArrayBuffer(base64);
      
      const importedKey = await crypto.subtle.importKey(
        "spki",
        binaryKey,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["encrypt"]
      );

      return importedKey;
    } catch (error) {
      console.error("❌ Errore importazione chiave pubblica:", error);
      throw error;
    }
  }

  /**
   * Importa una chiave privata da formato PEM
   * @param {string} pemKey - Chiave privata in formato PEM
   * @returns {Promise<CryptoKey>} Chiave privata importata
   */
  async importPrivateKey(pemKey) {
    try {
      // Rimuovi header/footer PEM e spazi
      const base64 = pemKey
        .replace('-----BEGIN PRIVATE KEY-----', '')
        .replace('-----END PRIVATE KEY-----', '')
        .replace(/\s/g, '');
      
      const binaryKey = this.base64ToArrayBuffer(base64);
      
      const importedKey = await crypto.subtle.importKey(
        "pkcs8",
        binaryKey,
        {
          name: "RSA-OAEP",
          hash: "SHA-256"
        },
        true,
        ["decrypt"]
      );

      return importedKey;
    } catch (error) {
      console.error("❌ Errore importazione chiave privata:", error);
      throw error;
    }
  }

  /**
   * Salva le chiavi nel localStorage del browser
   * @param {string} keyName - Nome base per le chiavi
   */
  async saveKeysToStorage(keyName = 'rsa_keys') {
    try {
      if (!this.keyPair) {
        throw new Error("Nessuna chiave da salvare");
      }

      const publicPem = await this.exportPublicKey();
      const privatePem = await this.exportPrivateKey();

      localStorage.setItem(`${keyName}_public`, publicPem);
      localStorage.setItem(`${keyName}_private`, privatePem);
      localStorage.setItem(`${keyName}_size`, this.keySize.toString());

      console.log(`💾 Chiavi salvate nel localStorage: ${keyName}_*`);
      
    } catch (error) {
      console.error("❌ Errore salvataggio chiavi:", error);
      throw error;
    }
  }

  /**
   * Carica le chiavi dal localStorage del browser
   * @param {string} keyName - Nome base delle chiavi
   */
  async loadKeysFromStorage(keyName = 'rsa_keys') {
    try {
      const publicPem = localStorage.getItem(`${keyName}_public`);
      const privatePem = localStorage.getItem(`${keyName}_private`);
      const keySize = localStorage.getItem(`${keyName}_size`);

      if (!publicPem || !privatePem) {
        throw new Error("Chiavi non trovate nel localStorage");
      }

      const publicKey = await this.importPublicKey(publicPem);
      const privateKey = await this.importPrivateKey(privatePem);

      this.keyPair = { publicKey, privateKey };
      this.keySize = keySize ? parseInt(keySize) : 2048;
      
      console.log(`📂 Chiavi caricate dal localStorage: ${keyName}_*`);
      return this.keyPair;
      
    } catch (error) {
      console.error("❌ Errore caricamento chiavi:", error);
      throw error;
    }
  }

  /**
   * Mostra informazioni sulle chiavi correnti
   */
  async getKeyInfo() {
    if (!this.keyPair) {
      console.log("❌ Nessuna chiave disponibile");
      return null;
    }

    try {
      const publicPem = await this.exportPublicKey();
      
      // Calcola hash della chiave pubblica
      const publicBytes = new TextEncoder().encode(publicPem);
      const hashBuffer = await crypto.subtle.digest('SHA-256', publicBytes);
      const hashArray = new Uint8Array(hashBuffer);
      const publicKeyHash = Array.from(hashArray)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .slice(0, 16);

      return {
        keySize: this.keySize,
        publicKeyLength: publicPem.length,
        publicKeyHash,
        maxMessageSize: Math.floor(this.keySize / 8) - 42,
        algorithm: 'RSA-OAEP',
        hash: 'SHA-256'
      };
    } catch (error) {
      console.error("❌ Errore info chiavi:", error);
      return null;
    }
  }

  // === UTILITY FUNCTIONS ===

  /**
   * Converte ArrayBuffer in string Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Converte string Base64 in ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

// === DEMO E TEST ===
async function demo() {
  console.log("🚀 RSA con Web Crypto API - Demo\n");

  const rsa = new WebCryptoRSA();

  try {
    // Genera chiavi per crittografia
    await rsa.generateKeyPair(2048);
    
    // Genera chiavi per firma
    await rsa.generateSigningKeyPair(2048);
    
    // Mostra info chiavi
    const info = await rsa.getKeyInfo();
    console.log("\n📊 Info Chiavi:", info);

    // Test crittografia semplice
    console.log("\n=== TEST CRITTOGRAFIA ===");
    const message = "Messaggio segreto con RSA e Web Crypto API!";
    console.log(`Messaggio originale: "${message}"`);
    console.log(`Lunghezza messaggio: ${message.length} caratteri (${new TextEncoder().encode(message).length} bytes)`);

    const encrypted = await rsa.encrypt(message);
    console.log(`Crittografato: ${encrypted.slice(0, 50)}...`);

    const decrypted = await rsa.decrypt(encrypted);
    console.log(`Decrittografato: "${decrypted}"`);
    console.log(`Test riuscito: ${message === decrypted ? '✅' : '❌'}`);

    // Test firma digitale
    console.log("\n=== TEST FIRMA DIGITALE ===");
    const document = "Documento importante da firmare";
    console.log(`Documento: "${document}"`);

    const signature = await rsa.sign(document);
    console.log(`Firma: ${signature.slice(0, 50)}...`);

    const isValid = await rsa.verify(document, signature);
    console.log(`Firma valida: ${isValid ? '✅' : '❌'}`);

    // Test con documento alterato
    const alteredDoc = "Documento ALTERATO da firmare";
    const isValidAltered = await rsa.verify(alteredDoc, signature);
    console.log(`Firma valida per documento alterato: ${isValidAltered ? '❌ ERRORE' : '✅ CORRETTO'}`);

    // Test messaggio lungo
    console.log("\n=== TEST MESSAGGIO LUNGO ===");
    const longMessage = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(20); // Messaggio lungo
    console.log(`Messaggio lungo: ${longMessage.length} caratteri (${new TextEncoder().encode(longMessage).length} bytes)`);

    const encryptedLong = await rsa.encryptLong(longMessage);
    console.log(`Blocchi crittografati: ${JSON.parse(encryptedLong).length}`);

    const decryptedLong = await rsa.decryptLong(encryptedLong);
    console.log(`Decrittografia lunga riuscita: ${longMessage === decryptedLong ? '✅' : '❌'}`);
    console.log(`Lunghezza originale: ${longMessage.length}, decrittografata: ${decryptedLong.length}`);

    // Test export/import chiavi
    console.log("\n=== TEST EXPORT/IMPORT CHIAVI ===");
    const publicPem = await rsa.exportPublicKey();
    console.log(`Chiave pubblica esportata: ${publicPem.slice(0, 50)}...`);

    const importedPublic = await rsa.importPublicKey(publicPem);
    const testEncrypted = await rsa.encrypt("Test import", importedPublic);
    const testDecrypted = await rsa.decrypt(testEncrypted);
    console.log(`Test import/export riuscito: ${testDecrypted === "Test import" ? '✅' : '❌'}`);

    // Salva chiavi nel localStorage (se disponibile)
    if (typeof Storage !== "undefined") {
      console.log("\n=== SALVATAGGIO CHIAVI ===");
      await rsa.saveKeysToStorage('demo_keys');
      console.log("💾 Chiavi salvate nel localStorage");
    }
    
    console.log("\n🎉 Demo completata con successo!");

  } catch (error) {
    console.error("💥 Errore durante la demo:", error);
  }
}

// Avvia la demo se il codice viene eseguito direttamente
if (typeof window !== 'undefined') {
  demo();
}