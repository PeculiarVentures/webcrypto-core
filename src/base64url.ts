// Fix btoa and atob for NodeJS
if (typeof self === "undefined") {
    const g = global as any;
    g.btoa = (data: string) => new Buffer(data, "binary").toString("base64");
    g.atob = (data: string) => new Buffer(data, "base64").toString("binary");
}

export class Base64Url {

    public static encode(value: Uint8Array): string {
        const str = this.buffer2string(value);
        const res = btoa(str)
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");
        return res;
    }

    public static decode(base64url: string): Uint8Array {
        while (base64url.length % 4) {
            base64url += "=";
        }
        const base64 = base64url
            .replace(/\-/g, "+")
            .replace(/_/g, "/");
        return this.string2buffer(atob(base64));
    }

    protected static buffer2string(buffer: Uint8Array) {
        let res = "";
        const len = buffer.length;
        for (let i = 0; i < len; i++) {
            res += String.fromCharCode(buffer[i]);
        }
        return res;
    }

    protected static string2buffer(binaryString: string) {
        const res = new Uint8Array(binaryString.length);
        const len = binaryString.length;
        for (let i = 0; i < len; i++) {
            res[i] = binaryString.charCodeAt(i);
        }
        return res;
    }

}
