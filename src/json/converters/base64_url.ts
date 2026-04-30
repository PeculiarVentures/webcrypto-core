import { IJsonConverter } from "@peculiar/json-schema";
import * as encoding from "@peculiar/utils/encoding";
import * as bytes from "@peculiar/utils/bytes";

export const JsonBase64UrlArrayBufferConverter: IJsonConverter<ArrayBuffer, string> = {
  fromJSON: (value: string) => bytes.toArrayBuffer(encoding.base64url.decode(value)),
  toJSON: (value: ArrayBuffer) => encoding.base64url.encode(value),
};
