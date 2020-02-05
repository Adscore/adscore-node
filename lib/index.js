/* eslint-env worker, browser, commonjs */

const crypto = require('crypto');

const IP6 = require('./ip6');

module.exports = class AdscoreSignature {
    constructor() {}

    static unpack(format, data) {
        let formatPointer = 0,
            dataPointer = 0,
            result = {},
            instruction = '',
            quantifier = '',
            label = '',
            currentData = '',
            i = 0,
            j = 0,
            dataByteLength = 0,
            currentResult = null;
        while (formatPointer < format.length) {
            instruction = format.charAt(formatPointer);
            quantifier = '';
            formatPointer++;
            while ((formatPointer < format.length) &&
                (format.charAt(formatPointer).match(/[\d\*]/) !== null)) {
                quantifier += format.charAt(formatPointer);
                formatPointer++;
            }
            if (quantifier === '')
                quantifier = '1';
            label = '';
            while ((formatPointer < format.length) && (format.charAt(formatPointer) !== '/'))
                label += format.charAt(formatPointer++);
            if (format.charAt(formatPointer) === '/')
                formatPointer++;
            switch (instruction) {
                case 'c':
                case 'C':
                    if (quantifier === '*')
                        quantifier = data.length - dataPointer;
                    else
                        quantifier = parseInt(quantifier, 10);
                    currentData = data.substr(dataPointer, quantifier);
                    dataPointer += quantifier;
                    for (i = 0; i < currentData.length; i++) {
                        currentResult = currentData.charCodeAt(i);
                        if ((instruction === 'c') && (currentResult >= 128))
                            currentResult -= 256;
                        result[label + (quantifier > 1 ? (i + 1) : '')] = currentResult;
                    }
                    break;
                case 'n':
                    if (quantifier === '*')
                        quantifier = (data.length - dataPointer) / 2;
                    else
                        quantifier = parseInt(quantifier, 10);
                    currentData = data.substr(dataPointer, quantifier * 2);
                    dataPointer += quantifier * 2;
                    for (i = 0; i < currentData.length; i += 2) {
                        currentResult = ((currentData.charCodeAt(i) & 0xFF) << 8) + (currentData.charCodeAt(i + 1) & 0xFF);
                        result[label + (quantifier > 1 ? ((i / 2) + 1) : '')] = currentResult;
                    }
                    break;
                case 'N':
                    if (quantifier === '*')
                        quantifier = (data.length - dataPointer) / 4;
                    else
                        quantifier = parseInt(quantifier, 10);
                    currentData = data.substr(dataPointer, quantifier * 4);
                    dataPointer += quantifier * 4;
                    for (i = 0; i < currentData.length; i += 4) {
                        currentResult =
                            ((currentData.charCodeAt(i) & 0xFF) << 24) +
                            ((currentData.charCodeAt(i + 1) & 0xFF) << 16) +
                            ((currentData.charCodeAt(i + 2) & 0xFF) << 8) +
                            ((currentData.charCodeAt(i + 3) & 0xFF));
                        result[label + (quantifier > 1 ? ((i / 4) + 1) : '')] = currentResult;
                    }
                    break;
                default:
                    throw new Error('unknown format code ' + instruction);
            }
        }
        return result;
    }

    static atob(str) {
      return Buffer.from(str, 'base64').toString('binary');
    }

    static fromBase64(data) {
        return this.atob(data.replace(/_/g, '/').replace(/-/g, '+'));
    }

    static parse3(signature) {
        signature = this.fromBase64(signature);
        if (!signature)
            throw new Error('invalid base64 payload');
        
        let data1 = this.unpack(
            'Cversion/NrequestTime/NsignatureTime/CmasterSignType/nmasterTokenLength',
            signature
        );
        
        if (data1.version != 3)
            throw new RangeError('unsupported version');
        
        if (data1.timestamp > (Date.now() / 1000))
            throw new Error('invalid timestamp (future time)');
        
        data1.masterToken = signature.substring(12, data1.masterTokenLength + 12);
        
        let s1, s2;

        if ((s1 = data1.masterTokenLength) != (s2 = data1.masterToken.length))
            throw new Error('master token length mismatch (' + s1 + ' / ' + s2 + ')');
        signature = signature.substring(data1.masterTokenLength + 12);
        
        let data2 = this.unpack('CcustomerSignType/ncustomerTokenLength', signature);
        data2.customerToken = signature.substring(3, data2.customerTokenLength + 3);
        if ((s1 = data2.customerTokenLength) != (s2 = data2.customerToken.length))
            throw new Error('customer token length mismatch (' + s1 + ' / ' + s2 + ')');

        return Object.assign({}, data1, data2);
    }

    static fieldTypeDef(fieldId, i) {
        const fieldIds = {
            0x00: {
                'name': 'requestTime',
                'type': 'ulong'
            },
            0x01: {
                'name': 'signatureTime',
                'type': 'ulong'
            },
            0x40: {
                'name': null,
                'type': 'ushort'
            },
            0x80: {
                'name': 'masterSignType',
                'type': 'uchar'
            },
            0x81: {
                'name': 'customerSignType',
                'type': 'uchar'
            },
            0xC0: {
                'name': 'masterToken',
                'type': 'string'
            },
            0xC1: {
                'name': 'customerToken',
                'type': 'string'
            },
            0xC2: {
                'name': 'masterTokenV6',
                'type': 'string'
            },
            0xC3: {
                'name': 'customerTokenV6',
                'type': 'string'
            }
        };
        if (fieldId in fieldIds)
            return fieldIds[fieldId];
        else
            return {
                'type': (fieldIds[fieldId & 0xC0].type),
                'name': (fieldIds[fieldId & 0xC0].type + i.toString(16).padStart(2, '0'))
            };
    }

    static parse4(signature) {
        signature = this.fromBase64(signature);
        if (!signature)
            throw new Error('invalid base64 payload');
        
        let data = this.unpack('Cversion/CfieldNum', signature);
        if (data.version != 4)
            throw new RangeError('unsupported version');
        signature = signature.substr(2);
        
        for (let i = 0; i < data.fieldNum; ++i) {
            let header = this.unpack('CfieldId', signature);
            if (!header || (!('fieldId' in header)))
                throw new Error('premature end of signature 0x01');
            
            let fieldTypeDef = this.fieldTypeDef(header.fieldId, i);
            let v, l;
            switch (fieldTypeDef.type) {
                case 'uchar':
                    v = this.unpack('Cx/Cv', signature);
                    if ('v' in v)
                        data[fieldTypeDef.name] = v.v;
                    else
                        throw new Error('premature end of signature 0x02');
                    signature = signature.substr(2);
                    break;
                case 'ushort':
                    v = this.unpack('Cx/nv', signature);
                    if ('v' in v)
                        data[fieldTypeDef.name] = v.v;
                    else
                        throw new Error('premature end of signature 0x03');
                    signature = signature.substr(3);
                    break;
                case 'ulong':
                    v = this.unpack('Cx/Nv', signature);
                    if ('v' in v)
                        data[fieldTypeDef.name] = v.v;
                    else
                        throw new Error('premature end of signature 0x04');
                    signature = signature.substr(5);
                    break;
                case 'string':
                    l = this.unpack('Cx/nl', signature);
                    if (!('l' in l))
                        throw new Error('premature end of signature 0x05');
                    if (l.l & 0x8000)
                        l.l = l.l & 0xFF;
                    data[fieldTypeDef.name] = v = signature.substr(3, l.l);
                    if (v.length != l.l)
                        throw new Error('premature end of signature 0x06');
                    signature = signature.substr(3 + l.l);
                    break;
                default:
                    throw new Error('unsupported variable type');
            }
        }
        delete data.fieldNum;

        return data;
    }

    static getBase(verdict, requestTime, signatureTime, ipAddress, userAgent) {
        return [verdict, requestTime, signatureTime, ipAddress, userAgent].join('\n');
    }

    static hashData(data, key) {
        return String.fromCharCode.apply(null, crypto.createHmac('sha256', key).update(data).digest());
    }

    static keyDecode(base64) {
        let raw = this.atob(base64);
        let rawLength = raw.length;
        let buf = new ArrayBuffer(rawLength);
        let array = new Uint8Array(buf);
        for (let i = 0; i < rawLength; i++) {
            array[i] = raw.charCodeAt(i);
        }
        return Buffer.from(buf);
    }

    static verify({ signature, ipAddresses, userAgent, signRole, key, expiry }) {
        try{
            if (!Array.isArray(ipAddresses))
                ipAddresses = [ipAddresses];

            let data;
            try {
                data = this.parse4(signature);
            } catch (err) {
                if (err instanceof RangeError)
                    data = this.parse3(signature);
                else
                    return {
                        error: err.message
                    };
            }
            if (!data[signRole + 'Token'])
                return {
                    error: 'sign role signature mismatch'
                };
            
            let signType = data[signRole + 'SignType'];
            ipAddressesLoop: for (let ipAddress of ipAddresses) {
                let token;
                if (!ipAddress)
                    continue ipAddressesLoop;
                if (IP6.validate(ipAddress)) {
                    if (!((signRole + 'TokenV6') in data))
                        continue ipAddressesLoop;
                    token = data[signRole + 'TokenV6'];
                    ipAddress = IP6.abbreviate(ipAddress);
                } else {
                    if (!((signRole + 'Token') in data))
                        continue ipAddressesLoop;
                    token = data[signRole + 'Token'];
                }
                let results = {
                    '0': 'ok',
                    '3': 'junk',
                    '6': 'proxy',
                    '9': 'bot'
                };
                resultLoop: for (let result in results) {
                    switch (signType) {
                        case 1:
                            let signatureBase = this.getBase(
                                result,
                                data.requestTime,
                                data.signatureTime,
                                ipAddress,
                                userAgent
                            );
                            if (this.hashData(signatureBase, key).localeCompare(token) == 0) {
                                if ((data.signatureTime + expiry) < Math.floor(Date.now() / 1000)){
                                    return {
                                        expired: true
                                    };
                                }
                                return {
                                    score: result,
                                    verdict: results[result],
                                    ipAddress: ipAddress,
                                    requestTime: data.requestTime,
                                    signatureTime: data.signatureTime
                                };
                            }
                            break;
                        case 2:
                            return {
                                error: 'unsupported signature'
                            };
                        default:
                            return {
                                error: 'unrecognized signature'
                            };
                    }
                }
            }
            return {
                error: 'no verdict'
            };
        }catch(err){
            return {
                error: err.message
            };
        }
    }
}