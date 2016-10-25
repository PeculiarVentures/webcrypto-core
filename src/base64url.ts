// Fix btoa and atob for NodeJS
if (typeof self === "undefined") {
    let _global = global as any;
    _global.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
    _global.atob = (data: string) => new Buffer(data, "base64").toString("binary");
}

export class Base64Url {

    protected static buffer2string(buffer: Uint8Array) {
        let res = "";
        for (let i = 0; i < buffer.length; i++)
            res += String.fromCharCode(buffer[i]);
        return res;
    }

    protected static string2buffer(binaryString: string) {
        let res = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++)
            res[i] = binaryString.charCodeAt(i);
        return res;
    }

    static encode(value: Uint8Array): string {
        const str = this.buffer2string(value);
        let res = btoa(str)
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        return res;
    }

    static decode(base64url: string): Uint8Array {
        while (base64url.length % 4) {
            base64url += "=";
        }
        const base64 = base64url
            .replace(/\-/g, "+")
            .replace(/_/g, "/");
        return this.string2buffer(atob(base64));
    }
}