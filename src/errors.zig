// framing errors (0xfe header, varint lengths, batch limits)
pub const FramingError = error{
    MalformedBatch,
    LimitExceeded,
    NoSpaceLeft,
};

pub const CompressionError = error{
    UnsupportedCompression,
    UnexpectedCompression,
    MalformedCompressedData,
    LimitExceeded,
    NoSpaceLeft,
};

pub const CryptoError = error{
    ChecksumMismatch,
    CounterExhausted,
    InvalidPublicKey,
    InvalidSalt,
    SessionClosed,
    NoSpaceLeft,
};

pub const AuthError = error{
    AuthenticationFailed,
    UntrustedChain,
    InvalidClaims,
    InvalidToken,
    InvalidSignature,
    UnsupportedAlgorithm,
    ExpiredToken,
    TokenNotYetValid,
    UnknownKey,
    AmbiguousKey,
    LimitExceeded,
    InvalidJson,
    InvalidUtf8,
    OutOfMemory,
};

pub const ResourcePackError = error{
    ResourcePackRejected,
    DuplicatePack,
    UnknownPack,
    InvalidChunk,
    IntegrityMismatch,
    IncompleteTransfer,
    LimitExceeded,
    InvalidUtf8,
};

pub const SessionError = error{
    InvalidState,
    UnsupportedProtocol,
    Unauthenticated,
    TransportClosed,
    InvalidLimits,
    OutOfMemory,
} || FramingError || CompressionError || CryptoError;
