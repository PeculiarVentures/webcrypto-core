function printf(text: string, ...args: any[]) {
    let msg: string = text;
    let regFind = /[^%](%\d+)/g;
    let match: RegExpExecArray | null;
    let matches: { arg: string, index: number }[] = [];
    while (match = regFind.exec(msg)) {
        matches.push({ arg: match[1], index: match.index });
    }

    // replace matches
    for (let i = matches.length - 1; i >= 0; i--) {
        let item = matches[i];
        let arg = item.arg.substring(1);
        let index = item.index + 1;
        msg = msg.substring(0, index) + arguments[+arg] + msg.substring(index + 1 + arg.length);
    }

    // convert %% -> %
    msg = msg.replace("%%", "%");

    return msg;
}

export class WebCryptoError extends Error {

    code = 0;
    stack: string;

    constructor(template: string, ...args: any[]) {
        super();
        this.message = printf(template, ...args as any);
        let error = new Error(this.message);
        error.name = (this as any)["constructor"].name;
        this.stack = (error as any).stack;
    }

    static NOT_SUPPORTED = "Method is not supported";
}

export class AlgorithmError extends WebCryptoError {
    code = 1;
    static PARAM_REQUIRED = "Algorithm hasn't got required paramter '%1'";
    static PARAM_WRONG_TYPE = "Algorithm has got wrong type for paramter '%1'. Must be %2";
    static PARAM_WRONG_VALUE = "Algorithm has got wrong value for paramter '%1'. Must be %2";
    static WRONG_ALG_NAME = "Algorithm has got wrong name '%1'. Must be '%2'";
    static UNSUPPORTED_ALGORITHM = "Algorithm '%1' is not supported";
    static WRONG_USAGE = "Algorithm doesn't support key usage '%1'";
}

export class CryptoKeyError extends WebCryptoError {
    code = 3;
    static EMPTY_KEY = "CryptoKey is empty";
    static WRONG_KEY_ALG = "CryptoKey has wrong algorithm '%1'. Must be '%2'";
    static WRONG_KEY_TYPE = "CryptoKey has wrong type '%1'. Must be '%2'";
    static WRONG_KEY_USAGE = "CryptoKey has wrong key usage. Must be '%1'";
    static NOT_EXTRACTABLE = "CryptoKey is not extractable";
    static WRONG_FORMAT = "CryptoKey has '%1' type. It can be used with '%2' format";
    static UNKNOWN_FORMAT = `Uknown format in use '%1'. Must be one of 'raw', 'pkcs8', 'spki'  or 'jwk'`;
    static ALLOWED_FORMAT = `Wrong format value '%1'. Must be %2`;
}