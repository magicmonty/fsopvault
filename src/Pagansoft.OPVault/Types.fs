namespace Pagansoft.OPVault

type UUID = UUID of string

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
  | CouldNotDecryptItem
  | CouldNotDecryptItemKey
  | EmptyCipherText
  | InvalidCipherText
  | OPDataIsNotDecrypted

type BandFileError =
  | InvalidBandFileFormat
  | UnknownCategory of string
  
type VaultError =
  | VaultIsLocked 

type OPVaultError =
  | FileError of FileError
  | ProfileError of ProfileError
  | ParserError of ParserError
  | OPDataError of OPDataError
  | BandFileError of BandFileError
  | VaultError of VaultError
  | UnknownError of string