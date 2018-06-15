namespace Pagansoft.OPVault

type Category =
  | Login
  | CreditCard
  | SecureNote
  | Identity
  | Password
  | TombStone
  | SoftwareLicense
  | BankAccount
  | Database
  | DriverLicense
  | OutdoorLicense
  | Membership
  | Passport
  | Rewards
  | SSN
  | Router
  | Server
  | Email

module Category =

  let fromCode (code: string) =
    match code with
    | "001" -> Ok Login
    | "002" -> Ok CreditCard
    | "003" -> Ok SecureNote
    | "004" -> Ok Identity
    | "005" -> Ok Password
    | "099" -> Ok TombStone
    | "100" -> Ok SoftwareLicense
    | "101" -> Ok BankAccount
    | "102" -> Ok Database
    | "103" -> Ok DriverLicense
    | "104" -> Ok OutdoorLicense
    | "105" -> Ok Membership
    | "106" -> Ok Passport
    | "107" -> Ok Rewards
    | "108" -> Ok SSN
    | "109" -> Ok Router
    | "110" -> Ok Server
    | "111" -> Ok Email 
    | code -> UnknownCategory code |> BandFileError |> Error

  let toCode (category: Category) : string =
    match category with
    | Login -> "001"
    | CreditCard -> "002"
    | SecureNote -> "003"
    | Identity -> "004"
    | Password -> "005"
    | TombStone -> "099" 
    | SoftwareLicense -> "100"
    | BankAccount -> "101"
    | Database -> "102"
    | DriverLicense -> "103"
    | OutdoorLicense -> "104"
    | Membership -> "105"
    | Passport -> "106"
    | Rewards -> "107"
    | SSN -> "108"
    | Router -> "109"
    | Server -> "110"
    | Email -> "111"