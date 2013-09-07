lockify.sjclBridge.decrypt = {
    hasHmac: function (ct){
        return ct.match(/\n\n[0-9a-zA-Z\+\/]{43}=$/) != null;
    },

    confirmHmac: function (keyString, ct_hmac){
        var keyBits = sjcl.codec.base64.toBits(keyString);
        var ciphertext = ct_hmac.substr(0, ct_hmac.length-45);
        var hmacString = ct_hmac.substr(ct_hmac.length-44);

        var newHmacString = "";
        var offset = 0;
        var size = lockifyGlobals.HMAC_BLOCK_CHAR_COUNT;
        var newHmac = new sjcl.misc.hmac(keyBits);
        if (ciphertext.length <= size) {
            // HMAC "short" ciphertexts with a single call.
            newHmacString = sjcl.codec.base64.fromBits(newHmac.encrypt(ciphertext));
        } else {
            // Longer ciphertexts (only those containing longer files) need
            // to use update() from a SJCL feature branch.
            while (offset <= ciphertext.length) {
                newHmac.update(ciphertext.slice(offset, offset + size));
                offset = offset + size;
            }
            newHmacString = sjcl.codec.base64.fromBits(newHmac.digest());
        }
        return (hmacString === newHmacString);
    },

    decrypts: function (ciphertext, keyString) {
        /*
        Synchronously decrypt an OpenSSL-compatible Base64 ciphertext
        string with the given Base64-encoded key.

        Since this function decrypts all the data at once,
        it should only be used for relatively short strings where
        performance and memory use won't become issues.
        */
        var key = sjcl.codec.base64.toBits(keyString),
            output = new sjclE.cbc.ByteStringOutput(),
            engine = new sjclE.cbc.OpenSSLWordStreamDecryptor(key, output),
            decoder = new sjclE.cbc.Base64WithBreaksByteDecoder(engine);
        if (ciphertext) {
            decoder.writeData(ciphertext);
            decoder.close();
        return decodeURIComponent(escape(output.getResult()));
        }
        else {
            return null;
        }
    },

    decryptData: function (keyString, bitStrength, ciphertext, callback) {
        var keyBits = sjcl.codec.base64.toBits(keyString);

        var BLOCK_SIZE = 8192, filelist = [],
            output = new sjclE.cbc.ByteStringOutput(), //new ByteArrayOutput(),
            offset = 0, size = ciphertext.length,
            engine = new sjclE.cbc.OpenSSLWordStreamDecryptor(keyBits,
                output),
            decoder = new sjclE.cbc.Base64WithBreaksByteDecoder(engine),
            nextChunk = function () {
                var message;
                var chunk = ciphertext.substr(0, BLOCK_SIZE);
                ciphertext = ciphertext.substr(BLOCK_SIZE);
                decoder.writeData(chunk);
                offset += BLOCK_SIZE;
                if (offset < size) {
                    var p = Math.floor(offset * 100 / size);
                    lockify.sjclBridge.throwEvent('dec-progress', [p]);
                    window.setTimeout(nextChunk, 1); // more data remains
                }
                else {  // done
                    decoder.close();
                    lockify.sjclBridge.throwEvent('dec-progress', [100]);
                    lockify.sjclBridge.throwEvent('dec-end');
                    window.status = 'Decryption complete.';
                    message = output.getResult();
                    if (message[0] === '\0') {
                        message = lockify.sjclBridge.decrypt.parsePlaintextMultifile(message, filelist);
                        // read format that allows attached files
                    }
                    // Decode UTF8 byte sequences in message to yield native
                    // JS Unicode string
                    message = decodeURIComponent(escape(message));
                    callback(message, filelist);
                }
            };

        lockify.sjclBridge.throwEvent('dec-start');
        nextChunk();
    },

    /**
     * Decode a plaintext message containing attachments.
     * Return the text of the message. Add records for each attached file to the
     * given filelist array (which generally starts empty).
     **/
    parsePlaintextMultifile: function (plaintext, filelist) {
        if (plaintext.charCodeAt(0) !== 0) {
            return false;
        }
        var pos = plaintext.indexOf('\0', 1),
            message = plaintext.substring(1, pos),
            itemLimit, filename, filesize;
        pos += 1;
        var count = 0;
        while (pos < plaintext.length) {
            // plaintext needs to be string and array so we switch back and forth
            if (typeof plaintext != "string") {
                plaintext = plaintext.join('');
            }
            itemLimit = plaintext.indexOf('\0', pos);
            // extract UTF-8 encoded filename
            if (itemLimit < 0) {
                throw 'Error: the message is corrupt.';
            }
            filename = decodeURIComponent(escape(
                plaintext.substring(pos, itemLimit)));
            pos = itemLimit + 1;
            itemLimit = plaintext.indexOf('\0', pos);
            if (itemLimit < 0) {
                throw 'Error: the message is corrupt.';
            }
            filesize = parseInt(plaintext.substring(pos, itemLimit), 10);
            pos = itemLimit + 1;
            if (pos + filesize > plaintext.length) {
                throw 'Error: the message is corrupt.';
            }
            file_plaintext = plaintext.substr(pos, filesize);
            plaintext = plaintext.substr(0, pos) + plaintext.substr(pos + filesize);
            filelist.push({
                filename: filename,
                file_plaintext: file_plaintext,
                length: filesize,
                readAsString: (function () {
                    return function () {
                        return this.file_plaintext;
                    };
                }()),
                readAsNumericByteArray: (function () {
                    return function () {
                        var arr = [], pos;
                        for (pos = 0; pos < this.file_plaintext.length; pos++) {
                            arr.push(this.file_plaintext[pos].charCodeAt(0));
                        }
                        return arr;
                    };
                }()),
                readSectionAsNumericByteArray: (function () {
                    return function (sectionStart, sectionLength, index) {
                        var arr = [], pos;
                        for (pos = sectionStart; pos < Math.min(sectionStart + sectionLength, this.file_plaintext.length); pos++) {
                            arr.push(this.file_plaintext[pos].charCodeAt(0));
                        }
                        lockify.sjclBridge.throwEvent('progress' + index, [pos/this.file_plaintext.length]);
                        return arr;
                    };
                }())
            });
            count++;
        }
        plaintext = null;
        return message;
    }
};
