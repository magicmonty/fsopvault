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
  open Newtonsoft.Json

  type FolderDTO = { uuid: string
                     overview: string
                     created: int
                     tx: int
                     updated: int
                     smart: System.Nullable<bool> }
                   
  let parseFolderItem (overviewKey: KeyPair) (prop: FolderDTO) : Result<Folder, OPVaultError> =
    trial {
      let! overview = prop.overview |> ByteArray.fromBase64 |> overviewKey.DecryptByteArray false
      
      return { UUID = prop.uuid
               Overview = overview |> Array.skipWhile (fun b -> b = 0uy) |> String.bytesAsString
               Created = prop.created |> DateTime.fromUnixTimeStamp
               TransactionTimeStamp = prop.tx |> DateTime.fromUnixTimeStamp
               Updated = prop.updated |> DateTime.fromUnixTimeStamp
               IsSmartFolder = prop.smart |> Option.fromNullable |> Option.defaultValue false }
    }
  
  let makeJSON content = 
    let startMarker = "loadFolders({"
    let endMarker = "});"

    content |> String.makeJSON startMarker endMarker

  let parseFolderFileJSON (json: string) : Result<Map<string, FolderDTO>, OPVaultError> =
    try
      JsonConvert.DeserializeObject<Map<string, FolderDTO>> json |> Ok
    with
    | _ -> JSONParserError json |> ParserError |> Error

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
                                                | Error e -> Error e) 
                |> Result.fold
      } 
    | Error e ->
      match e with
      | FileError (FileNotFound _) -> Ok []
      | _ -> Error e