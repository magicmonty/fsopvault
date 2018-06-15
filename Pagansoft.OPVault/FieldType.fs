namespace OPVault

type FieldType = 
  | Password
  | Text
  | Email
  | Number
  | Radio
  | Telephone
  | Checkbox
  | URL

module FieldType =
  let fromCode (code: string) : FieldType option =
    match code with
    | "P" -> Some Password
    | "T" -> Some Text
    | "E" -> Some Email
    | "N" -> Some Number
    | "R" -> Some Radio
    | "TEL" -> Some Telephone
    | "C" -> Some Checkbox
    | "U" -> Some URL
    | _ -> None

  let toCode (fieldType: FieldType) : string =
    match fieldType with
    | Password -> "P"
    | Text -> "T"
    | Email -> "E"
    | Number -> "N"
    | Radio -> "R"
    | Telephone -> "TEL"
    | Checkbox -> "C"
    | URL -> "U"