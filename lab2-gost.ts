
// gost28147-89 cryptosystem implementation in typescript
// loudn - 2024

// utilities
import { createInterface } from 'readline';

const rl = createInterface({
    input: process.stdin,
    output: process.stdout
})

function inputFunc(question: string): Promise<string> {
    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            resolve(answer)
        })
    })
}

// calculate the field alternative of a given number
const calculateNumberInField = (num: number, field: number): number => {
    while (num < field) num = num + field;
    return Math.abs(num) % field;
}

// unpack 2d array into the string
const arr2string = (array: string[]): string => {
    return array.flat().join('');
}

// add zeros to the bit sequence if needed
const parseBin = (num: number, blockSize: number): string => {
    let numStr = num.toString(2);
    while (numStr.length < blockSize) numStr = '0' + numStr;
    return numStr;
}

// map characters in messages in binary ASCII codes
const splitMsg = (text: string, mode: string = 'c'): string[] => {
    let asciiText: string[] = [];

    text.split('').forEach(element => {
        if (element === ' ') asciiText.push('00010000');
        else {
            let currentElem: string = '';
            if (mode === 'c') currentElem = Number(element.charCodeAt(0) - 880).toString(2)
            else if (mode === 'l') currentElem = Number(element.charCodeAt(0) + 100).toString(2)
            asciiText.push(currentElem);
        }
    });

    return asciiText;
}

// assemble msg from bits to chars
const assembleMsg = (binSequence: string, mode: string = 'c'): string => {
    let text: string = '';

    for (let i = 0; i < binSequence.length; i += 8) {
        const binBuffer: string = binSequence.slice(i, i + 8);

        if (binBuffer === '00010000') text += ' ';
        else if (mode === 'c') text += String.fromCharCode(parseInt(binBuffer, 2) + 880);
        else if (mode === 'l') text += String.fromCharCode(parseInt(binBuffer, 2) - 100);
    }
    return text;
}

// split string into chunks for more than one block coding mode
function splitStringIntoChunks(str: string, chunkSize: number): string[] {
    const chunks = [];
    for (let i = 0; i < str.length; i += chunkSize) {
        chunks.push(str.slice(i, i + chunkSize));
    }
    return chunks;
}

// gost28147-89 algorithm modules

// ASCII binary representation of given chracters
const initMsg = (text: string, langMode: string): string[][] => {
    const asciiText = splitMsg(text, langMode);
    return [asciiText.slice(0, Math.floor(asciiText.length / 2)), asciiText.slice(Math.floor(asciiText.length / 2), asciiText.length)];
}

// key storage device aka round keys generator for 256 bit input key
// returns 8 round keys (k0, k1, ..., k7)
const KSD = (text: string): string[] => {
    const asciiText: string[] = splitMsg(text);
    let keys: string[] = [];

    for (let i = 0; i < asciiText.length; i += 4) keys.push(asciiText.slice(i, i + 4).join(''));

    return keys;
}

// implementation of a single gost round
const gostRound = (left: string, right: string, roundKey: string, sBlock: number[][]): string => {
    // function F(r[i], x[i]) = (r[i] + x[i] % 2^32
    const F = (right: string, roundKey: string): string => {
        const field: number = Math.pow(2, 32);
        let sum: number = parseInt(right, 2) + parseInt(roundKey, 2);
        sum = calculateNumberInField(sum, field);

        return parseBin(sum, 32);
    }

    // S-blocks substitution
    const substitution = (sequence: string): string => {
        // split sequnce into blocks of size 4
        let sequenceSplitted: number[] = [];
        for (let i = 0; i < sequence.length; i += 4) sequenceSplitted.push(parseInt(sequence.slice(i, i + 4), 2));

        // iterate over sBlock to get the values for substitution
        let sequenceParsed: string[] = [];
        for (let i = 0; i < sequenceSplitted.length; i++) {
            sequenceParsed.push(parseBin(sBlock[sequenceSplitted[i]][i], 4));
        }
        return sequenceParsed.join('');
    }

    // byte shifting process (by default in gost the shift value is 11)
    const byteShift = (sequence: string, shiftValue: number): string => {
        // resolve the shift amount
        let shiftAmount = shiftValue % sequence.length;
        // shift the byte string
        let shiftedString = sequence.slice(shiftAmount) + sequence.slice(0, shiftAmount);

        return shiftedString;
    }

    // left block of data XOR with function F output
    const leftXORF = (fRes: string, left: string): string => {
        // bitwise XOR
        let result: string = '';
        for (let i = 0; i < left.length; i++) result += left[i] !== fRes[i] ? '1' : '0';

        return result;
    }

    // value of shift for the step three (byte shift operation)
    // for gost default is 11 
    const shiftValue: number = 11;

    const stepOne: string = F(right, roundKey);
    const stepTwo: string = substitution(stepOne);
    const stepThree: string = byteShift(stepTwo, shiftValue);
    const stepFour: string = leftXORF(stepThree, left);

    return stepFour;
}

const gostCryptosystem = (message: string, key: string, encrypting: boolean): string => {
    // round keys managment module
    const gostKeyMgmt = (keyInd: number, iteration: number, encrypting: boolean): number => {
        if (encrypting) {
            if (iteration === 23) keyInd = 7;
            else if (iteration < 24) {
                keyInd++;
                if (keyInd > 7) keyInd = 0;
            }
            else if (iteration > 23) keyInd--;
        }
        else {
            if (keyInd === 0 && iteration !== 0) keyInd = 7;
            else if (iteration === 7) keyInd = 7;
            else if (iteration < 7) keyInd++;
            else if (iteration > 7) keyInd--;
        }

        return keyInd;
    }

    // convert input data to ASCII
    // split the message into the left and right blocks
    let left: string = '';
    let right: string = '';

    const middleInd: number = Math.floor(message.length / 2);
    const msgSplitted: string[] = [message.slice(0, middleInd), message.slice(middleInd)];
    left = msgSplitted[0];
    right = msgSplitted[1];


    // key generation
    const keyRaw: string[] = KSD(key);

    // const filepath = '/Users/loudn/lab/jsPractice/cryptoProtocols/lab2/sblock.json';
    // const sBlock: number[][] | string = readFromJson(filepath);
    const sBlock: number[][] | string = [
        [1, 13, 4, 6, 7, 5, 14, 4],
        [15, 11, 11, 12, 13, 8, 11, 10],
        [13, 4, 10, 7, 10, 1, 4, 9],
        [0, 1, 0, 1, 1, 13, 12, 2],
        [5, 3, 7, 5, 0, 10, 6, 13],
        [7, 15, 2, 15, 8, 3, 13, 8],
        [10, 5, 1, 13, 9, 4, 15, 0],
        [4, 9, 13, 8, 15, 2, 10, 14],
        [9, 0, 3, 4, 14, 14, 2, 6],
        [2, 10, 6, 10, 4, 15, 3, 11],
        [3, 14, 8, 9, 6, 12, 8, 1],
        [14, 7, 5, 14, 12, 7, 1, 12],
        [6, 6, 9, 0, 11, 6, 0, 7],
        [11, 8, 12, 3, 2, 0, 7, 15],
        [8, 2, 15, 11, 5, 9, 5, 5],
        [12, 12, 14, 2, 3, 11, 9, 3]]

    // set the key index in KSD for the first round
    let keyInd: number = 0;

    // gost28147 encrypting/decrypting process (32 rounds)
    const roundsCount: number = 32;
    let buffer: string = '';

    for (let i = 0; i < roundsCount; i++) {
        buffer = `${right}`;
        right = gostRound(left, right, keyRaw[keyInd], sBlock);

        left = `${buffer}`;

        keyInd = gostKeyMgmt(keyInd, i, encrypting);
    }

    return right + left;
}

async function main(): Promise<void> {
    while (true) {
        // const message: string = 'кулешов ';
        // const key: string = 'алексеевалексеевалексеевалексеев';
        let message: string = await inputFunc('message to encrypt/decrypt (max 64 bit - 8 characters): ');
        const key: string = await inputFunc('encryption key (max 256 bit - 32 characters): ')
        const langMode: string = await inputFunc('choose language mode (c: ciryllic, l: latin): ')
        const mode: string = await inputFunc('choose mode (enc: encrypting, dec: decryption): ')

        if (mode === 'enc') {
            let messageBlocks: string[] = [];
            let encryptedMsg: string = '';

            if (message.length > 8) {
                messageBlocks = splitStringIntoChunks(message, 8);

                messageBlocks.forEach((substring) => {
                    // append spaces to the end in case the length of message is less than 8 byte (64 bit block)
                    while (substring.length < 8) substring += ' ';

                    // convert message into the bit sequence (ASCII)
                    let cleartext: string = arr2string(initMsg(substring, langMode)[0]) + arr2string(initMsg(substring, langMode)[1]);
                    console.log(`cleartext: ${cleartext}`);

                    // encrypt with gost algorithm
                    encryptedMsg += gostCryptosystem(cleartext, key, true);
                })
            } else {
                // append spaces to the end in case the length of message is less than 8 byte (64 bit block)
                while (message.length < 8) message += ' ';

                // convert message into the bit sequence (ASCII)
                let cleartext: string = arr2string(initMsg(message, langMode)[0]) + arr2string(initMsg(message, langMode)[1]);
                console.log(`cleartext: ${cleartext}`);

                // encrypt with gost algorithm
                encryptedMsg = gostCryptosystem(cleartext, key, true);
            }

            console.log(`encrypted message: ${encryptedMsg}\n`);

        } else if (mode === 'dec') {
            let messageBlocks: string[] = [];
            let decryptedMsg: string = '';

            if (message.length > 64) {
                messageBlocks = splitStringIntoChunks(message, 64);

                messageBlocks.forEach((substring) => {
                    // decrypt with gost algorithm
                    decryptedMsg += gostCryptosystem(substring, key, false);
                })
            } else {
                // decrypt with gost algorithm
                decryptedMsg += gostCryptosystem(message, key, false);
            }

            console.log(`\ndecrypted message: ${decryptedMsg}`);
            console.log(`decrypted message in characters: ${assembleMsg(decryptedMsg, langMode)}\n`);
        } else console.log('unexpected option\ntry again')
    }
}

main();
