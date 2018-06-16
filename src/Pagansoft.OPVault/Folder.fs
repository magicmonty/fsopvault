namespace Pagansoft.OPVault

open System

type Folder = { UUID: string
                Overview: string
                Created: DateTime
                TransactionTimeStamp: DateTime
                Updated: DateTime 
                IsSmartFolder: bool }

module Folder =
  open FSharp.Results
  open FSharp.Results.Results
  open Chiron

  type FolderDTO = { UUID: string
                     Overview: string
                     Created: int
                     TransactionTimeStamp: int
                     Updated: int
                     IsSmartFolder: bool }
                   
                   static member FromJson (_ : FolderDTO) : Json<FolderDTO> =
                    json {
                      let! created = Json.read "created"
                      let! overview = Json.read "overview"
                      let! tx = Json.read "tx"
                      let! updated = Json.read "updated"
                      let! smart = Json.tryRead "smart"
                      let! uuid = Json.read "uuid"
                      return { UUID = uuid
                               Overview = overview
                               Created = created
                               TransactionTimeStamp = tx
                               Updated = updated
                               IsSmartFolder = smart |> Option.defaultValue false }
                    }

  let parseFolderItem (overviewKey: KeyPair) (prop: FolderDTO) : Result<Folder, OPVaultError> =
    trial {
      let! overview = prop.Overview |> ByteArray.fromBase64 |> overviewKey.DecryptByteArray false
      
      return { UUID = prop.UUID
               Overview = overview |> Array.skipWhile (fun b -> b = 0uy) |> String.bytesAsString
               Created = prop.Created |> DateTime.fromUnixTimeStamp
               TransactionTimeStamp = prop.TransactionTimeStamp |> DateTime.fromUnixTimeStamp
               Updated = prop.Updated |> DateTime.fromUnixTimeStamp
               IsSmartFolder = prop.IsSmartFolder }
    }
  
  let makeJSON content = 
    let startMarker = "loadFolders({"
    let endMarker = "});"

    content |> String.makeJSON startMarker endMarker

  let parseFolderFileJSON (json: string) : Result<Map<string, FolderDTO>, OPVaultError> =
    try
      Json.parse json |> Json.deserialize |> Ok
    with
    | e -> JSONParserError e.Message |> ParserError |> Result.Error

  let read (profile: DecryptedProfileData) (vaultDir: string) =
    let filename = sprintf "%s/folders.js" vaultDir
    match File.read filename with
    | Ok content ->
      trial {
        let! json = content |> makeJSON
        let! items = json |> parseFolderFileJSON
        return! items 
                |> Map.toList
                |> List.map (fun (key, item) -> match item |> parseFolderItem profile.OverviewKey with
                                                | Ok item -> Ok (key, item)
                                                | Result.Error e -> Result.Error e) 
                |> Result.fold
      } 
    | Result.Error e ->
      match e with
      | FileError (FileNotFound _) -> Ok []
      | _ -> Result.Error e