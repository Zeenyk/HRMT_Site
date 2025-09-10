/**
 * RSA Encryption/Decryption usando Node.js crypto module
 * Implementazione per server-side con npm crypto
 */

const crypto = require("crypto");
const fs = require('fs');

class NodeRSA {
  constructor() {
    this.keyPair = null;
    this.keySize = 2048;
  }

  /**
   * Genera una nuova coppia di chiavi RSA
   * @param {number} keySize - Dimensione chiave in bit (default: 2048)
   * @returns {Object} Coppia di chiavi
   */
  generateKeyPair(keySize = 2048) {
    try {
      console.log(`🔑 Generando coppia chiavi RSA ${keySize}-bit...`);
      
      this.keySize = keySize;
      
      // Genera chiavi in modo sincrono
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });

      this.keyPair = { publicKey, privateKey };
      
      console.log("✅ Chiavi generate con successo!");
      console.log(`📏 Dimensione modulo: ${keySize} bit`);
      
      return this.keyPair;
      
    } catch (error) {
      console.error("❌ Errore generazione chiavi:", error);
      throw error;
    }
  }

  /**
   * Genera chiavi in modo asincrono (non bloccante)
   * @param {number} keySize - Dimensione chiave in bit
   * @returns {Promise<Object>} Coppia di chiavi
   */
  async generateKeyPairAsync(keySize = 2048) {
    return new Promise((resolve, reject) => {
      console.log(`🔑 Generando chiavi RSA ${keySize}-bit (async)...`);
      
      crypto.generateKeyPair('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      }, (err, publicKey, privateKey) => {
        if (err) {
          console.error("❌ Errore generazione chiavi:", err);
          reject(err);
        } else {
          this.keyPair = { publicKey, privateKey };
          this.keySize = keySize;
          console.log("✅ Chiavi generate con successo (async)!");
          resolve(this.keyPair);
        }
      });
    });
  }

  /**
   * Cripta un messaggio usando la chiave pubblica
   * @param {string} plaintext - Testo in chiaro
   * @param {string} publicKey - Chiave pubblica PEM (opzionale)
   * @returns {string} Messaggio crittografato (base64)
   */
  encrypt(plaintext, publicKey = null) {
    try {
      const key = publicKey || this.keyPair.publicKey;
      if (!key) {
        throw new Error("Nessuna chiave pubblica disponibile");
      }

      // Calcola dimensione massima del messaggio
      const maxMessageLength = Math.floor(this.keySize / 8) - 42; // OAEP padding
      
      if (Buffer.byteLength(plaintext, 'utf8') > maxMessageLength) {
        throw new Error(`Messaggio troppo lungo. Max ${maxMessageLength} bytes per chiave ${this.keySize}-bit`);
      }

      // Cripta usando RSA-OAEP con SHA-256
      const encrypted = crypto.publicEncrypt({
        key: key,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, Buffer.from(plaintext, 'utf8'));

      const base64Result = encrypted.toString('base64');
      
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
   * @param {string} privateKey - Chiave privata PEM (opzionale)
   * @returns {string} Testo in chiaro
   */
  decrypt(ciphertext, privateKey = null) {
    try {
      const key = privateKey || this.keyPair.privateKey;
      if (!key) {
        throw new Error("Nessuna chiave privata disponibile");
      }

      // Converte da base64 e decripta
      const encryptedBuffer = Buffer.from(ciphertext, 'base64');
      
      const decrypted = crypto.privateDecrypt({
        key: key,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      }, encryptedBuffer);

      const plaintext = decrypted.toString('utf8');
      
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
   * @param {string} privateKey - Chiave privata PEM (opzionale)
   * @returns {string} Firma digitale (base64)
   */
  sign(message, privateKey = null) {
    try {
      const key = privateKey || this.keyPair.privateKey;
      if (!key) {
        throw new Error("Nessuna chiave privata disponibile");
      }

      const signature = crypto.sign('sha256', Buffer.from(message, 'utf8'), {
        key: key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      });

      const base64Signature = signature.toString('base64');
      
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
   * @param {string} publicKey - Chiave pubblica PEM (opzionale)
   * @returns {boolean} True se la firma è valida
   */
  verify(message, signature, publicKey = null) {
    try {
      const key = publicKey || this.keyPair.publicKey;
      if (!key) {
        throw new Error("Nessuna chiave pubblica disponibile");
      }

      const signatureBuffer = Buffer.from(signature, 'base64');
      
      const isValid = crypto.verify('sha256', Buffer.from(message, 'utf8'), {
        key: key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
      }, signatureBuffer);

      console.log(`🔍 Verifica firma: ${isValid ? '✅ VALIDA' : '❌ INVALIDA'}`);
      return isValid;
      
    } catch (error) {
      console.error("❌ Errore verifica firma:", error);
      return false;
    }
  }

  /**
   * Cripta messaggi lunghi dividendoli in blocchi
   * @param {string} plaintext - Testo lungo da crittografare
   * @param {string} publicKey - Chiave pubblica PEM (opzionale)
   * @returns {string} Array di blocchi crittografati (JSON)
   */
  encryptLong(plaintext, publicKey = null) {
    try {
      const maxChunkSize = Math.floor(this.keySize / 8) - 42;
      const chunks = [];
      
      // Dividi il messaggio in blocchi
      for (let i = 0; i < plaintext.length; i += maxChunkSize) {
        const chunk = plaintext.slice(i, i + maxChunkSize);
        const encryptedChunk = this.encrypt(chunk, publicKey);
        chunks.push(encryptedChunk);
      }

      console.log(`📦 Messaggio lungo diviso in ${chunks.length} blocchi`);
      return JSON.stringify(chunks);
      
    } catch (error) {
      console.error("❌ Errore crittografia lunga:", error);
      throw error;
    }
  }

  /**
   * Decripta messaggi lunghi ricostruendo dai blocchi
   * @param {string} encryptedChunks - Array di blocchi crittografati (JSON)
   * @param {string} privateKey - Chiave privata PEM (opzionale)
   * @returns {string} Testo in chiaro ricostruito
   */
  decryptLong(encryptedChunks, privateKey = null) {
    try {
      const chunks = JSON.parse(encryptedChunks);
      let plaintext = '';

      for (const chunk of chunks) {
        const decryptedChunk = this.decrypt(chunk, privateKey);
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
   * Salva le chiavi su file
   * @param {string} basePath - Path base per salvare i file
   */
  saveKeysToFile(basePath = './keys/rsa') {
    try {
      if (!this.keyPair) {
        throw new Error("Nessuna chiave da salvare");
      }

      // Crea directory se non esiste
      const dir = basePath.substring(0, basePath.lastIndexOf('/'));
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      // Salva chiavi
      fs.writeFileSync(`${basePath}_public.pem`, this.keyPair.publicKey);
      fs.writeFileSync(`${basePath}_private.pem`, this.keyPair.privateKey);

      console.log(`💾 Chiavi salvate: ${basePath}_public.pem e ${basePath}_private.pem`);
      
    } catch (error) {
      console.error("❌ Errore salvataggio chiavi:", error);
      throw error;
    }
  }

  /**
   * Carica le chiavi da file
   * @param {string} basePath - Path base dei file delle chiavi
   */
  loadKeysFromFile(basePath = './keys/rsa') {
    try {
      const publicKey = fs.readFileSync(`${basePath}_public.pem`, 'utf8');
      const privateKey = fs.readFileSync(`${basePath}_private.pem`, 'utf8');

      this.keyPair = { publicKey, privateKey };
      
      console.log(`📂 Chiavi caricate da: ${basePath}_*.pem`);
      return this.keyPair;
      
    } catch (error) {
      console.error("❌ Errore caricamento chiavi:", error);
      throw error;
    }
  }

  /**
   * Mostra informazioni sulle chiavi correnti
   */
  getKeyInfo() {
    if (!this.keyPair) {
      console.log("❌ Nessuna chiave disponibile");
      return null;
    }

    const publicKeyBuffer = Buffer.from(
      this.keyPair.publicKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, ''), 
      'base64'
    );

    return {
      keySize: this.keySize,
      publicKeyLength: this.keyPair.publicKey.length,
      privateKeyLength: this.keyPair.privateKey.length,
      publicKeyHash: crypto.createHash('sha256').update(publicKeyBuffer).digest('hex').slice(0, 16),
      maxMessageSize: Math.floor(this.keySize / 8) - 42
    };
  }
}

// === DEMO E TEST ===
async function demo() {
  console.log("🚀 RSA con Node.js crypto - Demo\n");

  const rsa = new NodeRSA();

  try {
    // Genera chiavi
    await rsa.generateKeyPairAsync(2048);
    
    // Mostra info chiavi
    const info = rsa.getKeyInfo();
    console.log("\n📊 Info Chiavi:", info);

    // Test crittografia semplice
    console.log("\n=== TEST CRITTOGRAFIA ===");
    const message = "Messaggio segreto con RSA e Node.js crypto! 🔐";
    console.log(`Messaggio originale: "${message}"`);

    const encrypted = rsa.encrypt(message);
    console.log(`Crittografato: ${encrypted.slice(0, 50)}...`);

    const decrypted = rsa.decrypt(encrypted);
    console.log(`Decrittografato: "${decrypted}"`);
    console.log(`Test riuscito: ${message === decrypted ? '✅' : '❌'}`);

    // Test firma digitale
    console.log("\n=== TEST FIRMA DIGITALE ===");
    const document = "Documento importante da firmare";
    console.log(`Documento: "${document}"`);

    const signature = rsa.sign(document);
    console.log(`Firma: ${signature.slice(0, 50)}...`);

    const isValid = rsa.verify(document, signature);
    console.log(`Firma valida: ${isValid ? '✅' : '❌'}`);

    // Test con documento alterato
    const alteredDoc = "Documento ALTERATO da firmare";
    const isValidAltered = rsa.verify(alteredDoc, signature);
    console.log(`Firma valida per documento alterato: ${isValidAltered ? '❌ ERRORE' : '✅ CORRETTO'}`);

    // Test messaggio lungo
    console.log("\n=== TEST MESSAGGIO LUNGO ===");
    const longMessage = "A".repeat(500); // Messaggio lungo
    console.log(`Messaggio lungo: ${longMessage.length} caratteri`);

    const encryptedLong = rsa.encryptLong(longMessage);
    console.log(`Blocchi crittografati: ${JSON.parse(encryptedLong).length}`);

    const decryptedLong = rsa.decryptLong(encryptedLong);
    console.log(`Decrittografia lunga riuscita: ${longMessage === decryptedLong ? '✅' : '❌'}`);

    // Salva chiavi (opzionale)
    console.log("\n=== SALVATAGGIO CHIAVI ===");
    rsa.saveKeysToFile('./demo_keys/my_rsa');
    
    console.log("\n🎉 Demo completata con successo!");

  } catch (error) {
    console.error("💥 Errore durante la demo:", error);
  }
}

// Avvia demo se eseguito direttamente
if (require.main === module) {
  demo();
}

module.exports = NodeRSA;