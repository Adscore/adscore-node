/* eslint-env worker, browser, commonjs */

module.exports = class IP6 {
    /** Created by elgs on 3/5/16. */
    static normalize(a) {
        if (!this.validate(a))
            throw new Error('Invalid address: ' + a);
        a = a.toLowerCase()
        let nh = a.split(/\:\:/g);
        if (nh.length > 2)
            throw new Error('Invalid address: ' + a);
        let sections = [];
        if (nh.length == 1) {
            sections = a.split(/\:/g);
            if (sections.length !== 8)
                throw new Error('Invalid address: ' + a);
        } else if (nh.length == 2) {
            let n = nh[0];
            let h = nh[1];
            let ns = n.split(/\:/g);
            let hs = h.split(/\:/g);
            for (let i in ns)
                sections[i] = ns[i];
            for (let i = hs.length; i > 0; --i)
                sections[7 - (hs.length - i)] = hs[i - 1];
        }
        for (let i = 0; i < 8; ++i) {
            if (sections[i] === undefined)
                sections[i] = '0000';
            sections[i] = this.leftPad(sections[i], '0', 4);
        }
        return sections.join(':');
    };
    static abbreviate(a) {
        if (!this.validate(a))
            throw new Error('Invalid address: ' + a);
        a = this.normalize(a);
        a = a.replace(/0000/g, 'g');
        a = a.replace(/\:000/g, ':');
        a = a.replace(/\:00/g, ':');
        a = a.replace(/\:0/g, ':');
        a = a.replace(/g/g, '0');
        let sections = a.split(/\:/g);
        let zPreviousFlag = false;
        let zeroStartIndex = -1;
        let zeroLength = 0;
        let zStartIndex = -1;
        let zLength = 0;
        for (let i = 0; i < 8; ++i) {
            let section = sections[i];
            let zFlag = (section === '0');
            if (zFlag && !zPreviousFlag)
                zStartIndex = i;
            if (!zFlag && zPreviousFlag)
                zLength = i - zStartIndex;
            if (zLength > 1 && zLength > zeroLength) {
                zeroStartIndex = zStartIndex;
                zeroLength = zLength;
            }
            zPreviousFlag = (section === '0');
        }
        if (zPreviousFlag)
            zLength = 8 - zStartIndex;
        if (zLength > 1 && zLength > zeroLength) {
            zeroStartIndex = zStartIndex;
            zeroLength = zLength;
        }
        if (zeroStartIndex >= 0 && zeroLength > 1)
            sections.splice(zeroStartIndex, zeroLength, 'g');
        a = sections.join(':');
        a = a.replace(/\:g\:/g, '::');
        a = a.replace(/\:g/g, '::');
        a = a.replace(/g\:/g, '::');
        a = a.replace(/g/g, '::');
        return a;
    };
    static validate(a) {
        return /^[a-f0-9\\:]+$/ig.test(a);
    };
    static leftPad(d, p, n) {
        let padding = p.repeat(n);
        if (d.length < padding.length) {
            d = padding.substring(0, padding.length - d.length) + d;
        }
        return d;
    };
}