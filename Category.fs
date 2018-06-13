namespace OPVault

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
  let fromCode (code: string) : Category option =
    match code with
    | "001" -> Some Login
    | "002" -> Some CreditCard
    | "003" -> Some SecureNote
    | "004" -> Some Identity
    | "005" -> Some Password
    | "099" -> Some TombStone
    | "100" -> Some SoftwareLicense
    | "101" -> Some BankAccount
    | "102" -> Some Database
    | "103" -> Some DriverLicense
    | "104" -> Some OutdoorLicense
    | "105" -> Some Membership
    | "106" -> Some Passport
    | "107" -> Some Rewards
    | "108" -> Some SSN
    | "109" -> Some Router
    | "110" -> Some Server
    | "111" -> Some Email 
    | _ -> None

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