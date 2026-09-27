/**
 * Every refusal of this library (bad input to a builder, malformed CBOR / UR / response) is a ProtoError, like
 * make_request.py's ProtoError. Verification failures are NOT thrown: they are failed checks in a VerifyReport.
 */
export class ProtoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtoError';
  }
}
