lockify.sjclBridge.encrypt = {
    encrypts: function (plaintextString, keyString, key) {
        /*
        Synchronously encrypt a plaintext Unicode string with a
        given Base64-encoded key, returning OpenSSL-compatible
        Base64 ciphertext.

        Since this function is synchronous, takes and returns data
        in monolithic strings, and doesn't return progress information,
        it should only be used for relatively short strings where
        performance and memory use won't become issues.
        */
        function utf8ToByteArray(str) {
            return sjcl.codec.bytes.fromBits(sjcl.codec.utf8String.toBits(str));
        }

        var iv;
        try {
            iv = getRandomWords(4);
        } catch (err) {
            alert('Could not generate random numbers. ' + err);
            return null;
        }
        var output = sjclE.cbc.StringOutput(),
            encryptor = sjclE.cbc.OpenSSLByteStreamEncryptor(key, iv,
            sjclE.cbc.Base64WithBreaksWordEncoder(output)),
            plaintextByteCodes = utf8ToByteArray(plaintextString);
        encryptor.writeData(plaintextByteCodes);
        encryptor.close();
        return output.getResult();
    },

    encryptData: function (data, encryption_type, callback) {

        function utf8ToByteArray(str) {
            return sjcl.codec.bytes.fromBits(sjcl.codec.utf8String.toBits(str));
        }

        var key, iv, keyString, hmacString;

        // create random bitArrays to use as the encryption key and iv
        //when the encrypt now is clicked set the values to the model
        if (encryption_type == "encryptMessage") {
            try {
                key = getRandomWords(data.get('bitStrength') / 32);
                iv = getRandomWords(4);
                keyString = sjcl.codec.base64.fromBits(key).replace(/\=+$/, '');

            } catch (err) {
                alert('Could not generate random numbers. ' + err);
                return false;
            }
        } else {
            //when lockify now is clicked get the values set in the model
            iv = lockify.index.entry.get('cryptoAssets').iv;
            key = lockify.index.entry.get('cryptoAssets').key;
            keyString = lockify.index.entry.get('cryptoAssets').keyString;
            hmacString = lockify.index.entry.get('cryptoAssets').hmacString;
        }

        var output = sjclE.cbc.StringOutput();
        var encryptor = sjclE.cbc.OpenSSLByteStreamEncryptor(key, iv,
        sjclE.cbc.Base64WithBreaksWordEncoder(output));
        var plaintextByteCodes = utf8ToByteArray(data.get('plaintext'));

        lockify.sjclBridge.throwEvent('enc-start');
        if (data.get('files') && data.get('files').length) {
            // Use data format that allows files, which is prefixed with
            // a null character.
            encryptor.writeData([0]);
        }

        var nextBlock = function () {
            // This function is called repeatedly to encrypt chunks of the
            // input, and maintains its own state. It returns false when the
            // entire task is done. The task is broken up into chunks so that
            // the browser remains responsive and any JavaScript CPU limits
            // aren't reached, which could result in a slow-script alert.
            // Since file reading may be asynchronous, maintain a 'blocked'
            // variable. When true, we're waiting for a read/encrypt to complete.
            var itemIndex = 0,
                offset = 0,
                BLOCK_SIZE = 4096,
                blocked = false;

            return function () {
                if (window.console) {
                    window.console.log('Encrypting segment', itemIndex, offset);
                }
                if (blocked) {
                    if (window.console) {
                        window.console.log('Spinning waiting for previous file read/encrypt to complete.');
                    }
                    return true;
                }
                var item, itemSize;
                if (itemIndex === 0) {
                    itemSize = plaintextByteCodes.length;
                    encryptor.writeData(plaintextByteCodes.slice(
                    offset, offset + BLOCK_SIZE));
                    offset += BLOCK_SIZE;
                    if (offset >= itemSize && data.get('files') && data.get('files').length) {
                        encryptor.writeData([0]);
                    }
                } else {
                    item = data.get('files')[itemIndex - 1];
                    if (item.asyncReader) {
                        if (offset < item.size) {
                            blocked = true;
                            item.asyncReader(function (data) {
                                offset += data.length;
                                encryptor.writeData(data);
                                blocked = false;
                            });
                        }
                    } else {
                        encryptor.writeData(item.reader(BLOCK_SIZE));
                        offset += BLOCK_SIZE;
                    }
                    itemSize = item.size;
                }
                if (!blocked && offset >= itemSize) {
                    // finished with current item; write header for next
                    itemIndex++;
                    if (data.get('files') && itemIndex <= data.get('files').length) {
                        item = data.get('files')[itemIndex - 1];
                        // Next item header
                        encryptor.writeData(utf8ToByteArray(item.filename));
                        encryptor.writeData([0].concat(
                        utf8ToByteArray('' + item.size), [0]));
                        offset = 0;
                        return true; // Need another round for next item
                    }
                    return false; // No more rounds: finished last item
                }
                return true; // Need another round: current item not done
            };
        }();

        function nextBlockWithTimeout() {
            if (encryption_type == 'encryptMessage') {
                if (nextBlock()) {
                    window.setTimeout(nextBlockWithTimeout, 1);
                    var progPercent = Math.min(1.0, output.getResult().length / data.finalTotalDataLength);
                    lockify.sjclBridge.throwEvent('enc-progress', progPercent);
                    if (window.console) { window.console.log("Encryption % complete:" + progPercent); }
                } else {
                    endEncryption();
                }
            }
            else {
                endAuthEncryption();
            }
        }

        window.setTimeout(nextBlockWithTimeout, 1);

        function endEncryption() {
            //when encrypt now is clicked
            encryptor.close();
            var ciphertext = output.getResult();

            //need to set the auth type only when lockify now is clicked
            var salt = generateRandomString(32);
            var adminCredPlain = generateRandomString(8);
            var adminCredHash = hash_sha256_b64u(salt + adminCredPlain);

            var authInfoKeyString = keyString;
            // TODO: support link-embedded ciphertext; above line currently requires link-embedded key only

            var hmacString;
            if (typeof hmacString === 'undefined'){

                var offset = 0;
                var size = lockifyGlobals.HMAC_BLOCK_CHAR_COUNT;
                var hmac = new sjcl.misc.hmac(key);
                if (ciphertext.length <= size) {
                    // HMAC "short" ciphertexts with a single call.
                    hmacString = sjcl.codec.base64.fromBits(hmac.encrypt(ciphertext));
                } else {
                    // Longer ciphertexts (only those containing longer files) need
                    // to use update() from a SJCL feature branch.
                    while (offset <= ciphertext.length) {
                        hmac.update(ciphertext.slice(offset, offset + size));
                        offset = offset + size;
                    }
                    hmacString = sjcl.codec.base64.fromBits(hmac.digest());
                }
            }

            callback({
                "salt": salt,
                "iv": iv,
                "key": key,
                "adminCredHash": adminCredHash,
                "passwordHash": '',
                "secAnsAcceptClose": '',
                "secAnHashes": '',
                "useridHashes": '',
                "useridsAES256": '',
                "keyString": keyString,
                "ciphertext": ciphertext + '\n' + hmacString
            });
            //moved at the end else the enc-end doesnt get triggered properly
            //for randomness.
            lockify.sjclBridge.throwEvent('enc-end');

        }
         //when encrypt now is clicked
        function endAuthEncryption() {

            encryptor.close();
            ciphertext = lockify.index.entry.get('cryptoAssets').ciphertext;
            lockify.sjclBridge.throwEvent('enc-auth');

            //need to set the auth type only when lockify now is clicked
            var salt = lockify.index.entry.get('cryptoAssets').salt;
            var adminCredPlain = lockify.index.entry.get('cryptoAssets').adminCredPlain;
            var adminCredHash = lockify.index.entry.get('cryptoAssets').adminCredHash;

            var passwordHash = '';
            var secAns = [];
            var secAnHashes = [];
            var secAnsAcceptClose = [];
            var useridHashes = '',
                useridsAES256 = '';
            var authInfoKeyString = keyString;
            // TODO: support link-embedded ciphertext; above line currently requires link-embedded key only
            switch (data.get('authMethod')) {
            case 'password':
                passwordHash = hash_sha256_b64u(salt + data.get('password'));
                break;
            case 'question':
                // Create array of answers
                secAns = data.get('securityAnswer').toLowerCase().split(',');
                // Process each answer
                $.each(secAns, function (i, val) {
                    // Remove leading and trailing whitespace
                    val = $.trim(val);
                    if (!val.length) { return; }

                    // If the user wants to accept 'close' answers and this answers is long enough...
                    if (data.get('acceptCloseAnswers') && val.replace(CLOSE_ANSWER_REGEX, '').length >= MIN_CHARS_ENABLE_CLOSE) {
                        // ...lower case the answer and remove all non-alphanumeric chanracters.
                        val = val.replace(CLOSE_ANSWER_REGEX, '');
                        secAnsAcceptClose[i] = true;
                    } else {
                        secAnsAcceptClose[i] = false;
                    }
                    // Hash and encode the security answer before transmitting.
                    val = hash_sha256_b64u(salt + val);
                    // Save the processed answer back to the array.
                    secAnHashes.push(val);
                });
                break;
            case 'native':
            case 'thirdParty':
            case 'phone':
            case 'email':
            case 'intEmail':
                // Make hashes of all the userids, so that the userids themselves
                // aren't sent to the server. The comma isn't a base64 symbol, so
                // it's still OK to join the resulting items with commas later.
                useridHashes = $.map(data.get('userids'), function (userid) {
                    var caseNormalUserIds = (data.get('authMethod') === "native") ? userid.toUpperCase() : userid.toLowerCase();
                    return hash_sha256_b64u(salt + caseNormalUserIds);
                });
                if (ENABLE_2WAY_USERID_CRYPTO) {
                    useridsAES256 = lockify.sjclBridge.encrypt.encrypts(data.maskedUserIds().join(', '), authInfoKeyString, key);
                }
                break;
            }
            callback({
                "salt": salt,
                "iv": iv,
                "key": key,
                "adminCredHash": adminCredHash,
                "passwordHash": passwordHash,
                "secAnsAcceptClose": secAnsAcceptClose,
                "secAnHashes": secAnHashes,
                "useridHashes": useridHashes,
                "useridsAES256": useridsAES256,
                "keyString": keyString,
                "ciphertext": ciphertext
            });

        }
    }
};
