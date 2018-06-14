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

  type OPDataError =
    | CouldNotAuthenticate
    | EmptyCipherText
    | OPDataIsNotDecrypted

  type OPVaultError =
    | FileError of FileError
    | ProfileError of ProfileError
    | ParserError of ParserError
    | OPDataError of OPDataError
    | UnknownError of string