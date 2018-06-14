namespace OPVault

module Errors =
  type ProfileError =
    | CouldNotReadProfile
    | ProfileNotFound
    | ProfileIsEncrypted
    | CouldNotFindOverviewKey
    | CouldNotFindMasterKey
    | UnknownProfileError of string

  type ParserError = int64 * string

  type OPDataError =
    | CouldNotAuthenticate
    | EmptyCipherText
    | OPDataIsNotDecrypted

  type OPVaultError =
    | ProfileError of ProfileError
    | ParserError of ParserError
    | OPDataError of OPDataError