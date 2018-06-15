namespace OPVault

type Designation =
  | NoDesignation
  | Username
  | Password

module Designation =
  let fromCode (code: string) : Designation =
    match code with
    | "username" -> Username
    | "password" -> Password
    | _ -> NoDesignation

  let toCode designation : string =
    match designation with
    | Username -> "username"
    | Password -> "password"
    | NoDesignation -> ""