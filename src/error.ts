function printf(text: string, ...args: any[]) {
    let msg: string = text;
    const regFind = /[^%](%\d+)/g;
    let match: RegExpExecArray | null;
    const matches: Array<{ arg: string, index: number }> = [];
    // tslint:disable-next-line:no-conditional-assignment
    while (match = regFind.exec(msg)) {
        matches.push({ arg: match[1], index: match.index });
    }

    // replace matches
    for (let i = matches.length - 1; i >= 0; i--) {
        const item = matches[i];
        const arg = item.arg.substring(1);
        const index = item.index + 1;
        msg = msg.substring(0, index) + arguments[+arg] + msg.substring(index + 1 + arg.length);
    }

    // convert %% -> %
    msg = msg.replace("%%", "%");

    return msg;
}

export class WebCryptoError extends Error {

    public static NOT_SUPPORTED = "Method is not supported";

    public code = 0;
    public stack: string;

    constructor(template: string, ...args: any[]) {
        super();
        this.message = printf(template, ...args as any);
        const error = new Error(this.message);
        error.name = (this as any).constructor.name;
        this.stack = (error as any).stack;
    }

}

export class AlgorithmError extends WebCryptoError {

    public static PARAM_REQUIRED = "Algorithm hasn't got required paramter '%1'";
    public static PARAM_WRONG_TYPE = "Algorithm has got wrong type for paramter '%1'. Must be %2";
    public static PARAM_WRONG_VALUE = "Algorithm has got wrong value for paramter '%1'. Must be %2";
    public static WRONG_ALG_NAME = "Algorithm has got wrong name '%1'. Must be '%2'";
    public static UNSUPPORTED_ALGORITHM = "Algorithm '%1' is not supported";
    public static WRONG_USAGE = "Algorithm doesn't support key usage '%1'";

    public code = 1;
}

export class CryptoKeyError extends WebCryptoError {
    public static EMPTY_KEY = "CryptoKey is empty";
    public static WRONG_KEY_ALG = "CryptoKey has wrong algorithm '%1'. Must be '%2'";
    public static WRONG_KEY_TYPE = "CryptoKey has wrong type '%1'. Must be '%2'";
    public static WRONG_KEY_USAGE = "CryptoKey has wrong key usage. Must be '%1'";
    public static NOT_EXTRACTABLE = "CryptoKey is not extractable";
    public static WRONG_FORMAT = "CryptoKey has '%1' type. It can be used with '%2' format";
    public static UNKNOWN_FORMAT = `Unknown format in use '%1'. Must be one of 'raw', 'pkcs8', 'spki'  or 'jwk'`;
    public static ALLOWED_FORMAT = `Wrong format value '%1'. Must be %2`;

    public code = 3;
}
