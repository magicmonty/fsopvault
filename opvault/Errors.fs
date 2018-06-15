namespace OPVault

module Errors =
  type FileError =
    | FileNotFound of string

  type ProfileError =
    | CouldNotReadProfile
    | ProfileNotFound
    | ProfileIsEncrypted
    | CouldNotFindOverviewKey
    | CouldNotFindMasterKey
    | UnknownProfileError of string

  type ParserError = 
    | BinaryParserError of int64 * string
    | JSONParserError of string
    | WrongFormatError

  type OPDataError =
    | CouldNotAuthenticate
    | CouldNotDecrypt
    | EmptyCipherText
    | InvalidCipherText
    | OPDataIsNotDecrypted

  type BandFileError =
    | InvalidBandFileFormat
    | UnknownCategory of string
    
  type OPVaultError =
    | FileError of FileError
    | ProfileError of ProfileError
    | ParserError of ParserError
    | OPDataError of OPDataError
    | BandFileError of BandFileError
    | UnknownError of string